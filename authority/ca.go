package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/mail"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	hqgotlsauthoritycache "github.com/hueristiq/hq-lib-tls-go/authority/cache"
)

const (
	// defaultCacheMaxAge is the default maximum age of a cached certificate before it is re-issued.
	defaultCacheMaxAge = time.Hour
	// defaultLeafCertificateValidity is the validity period of certificates issued dynamically
	// by the SNI-driven TLS configuration.
	defaultLeafCertificateValidity = 24 * time.Hour
)

const (
	// errCANil is returned by CA methods called on a nil receiver.
	errCANil hqgoerrors.Sentinel = "invalid input, CA is nil"
	// errCANotInitialized is returned by CA methods when the
	// authority is missing its CA certificate or private key.
	errCANotInitialized hqgoerrors.Sentinel = "invalid input, CA is not initialized"
)

// A CA generates and signs TLS certificates from a single CA certificate and
// its private key. It issues certificates dynamically for the hostname requested via Server Name
// Indication (SNI). Caching of issued certificates is opt-in: pass a [hqgotlsauthoritycache.Cache]
// via [WithCache] to reuse certificates across requests, or leave it unset (nil cache) to
// regenerate a certificate on every request.
//
// The zero value is not usable: construct a CA with [New] (from an in-memory
// certificate and key), with [NewFromPEM] (from PEM bytes), or generate a
// fresh CA first with [GenerateCACertificatePrivateKey].
//
// A CA is safe for concurrent use by multiple goroutines; the in-flight
// generation tracking is guarded by an internal mutex, and a configured cache must be safe
// for concurrent use as well.
//
// Fields:
//   - caCertificate (*x509.Certificate): the CA certificate used to sign issued certificates.
//   - caCertificatePrivateKey (crypto.Signer): the private key corresponding to the CA certificate.
//   - cache (hqgotlsauthoritycache.Cache): the cache of generated certificates, keyed by normalized hostname; nil disables caching.
//   - cacheMaxAge (time.Duration): the maximum age of a cached certificate before it is re-issued.
//   - ops (*operations): the cryptographic and filesystem operations to use; nil selects the production set.
//   - inflightMutex (sync.Mutex): guards inflight.
//   - inflight (map[string]*inflightCall): in-progress certificate generations, keyed by normalized hostname.
type CA struct {
	caCertificate           *x509.Certificate
	caCertificatePrivateKey crypto.Signer

	cache       hqgotlsauthoritycache.Cache
	cacheMaxAge time.Duration

	ops *operations

	inflightMutex sync.Mutex
	inflight      map[string]*inflightCall
}

// CACertificate returns a copy of the CA's X.509 certificate.
//
// The returned certificate is a shallow copy, so mutating its fields does not affect the authority.
func (ca *CA) CACertificate() (certificate *x509.Certificate) {
	if ca == nil || ca.caCertificate == nil {
		return nil
	}

	certificateCopy := *ca.caCertificate

	return &certificateCopy
}

// CACertificatePrivateKey returns the CA's private key.
func (ca *CA) CACertificatePrivateKey() (privateKey crypto.Signer) {
	if ca == nil {
		return nil
	}

	return ca.caCertificatePrivateKey
}

// isEmailAddress reports whether host is a bare [RFC 5322](https://www.rfc-editor.org/info/rfc5322/) email address (e.g.,
// "user@example.com"). The '@' gate lets plain DNS names skip the [RFC 5322](https://www.rfc-editor.org/info/rfc5322/)
// parser, which dominates host classification for the common case.
func isEmailAddress(host string) (isEmail bool) {
	if !strings.Contains(host, "@") {
		return false
	}

	email, err := mail.ParseAddress(host)

	return err == nil && email.Address == host
}

// dnsNameToASCII returns the ASCII form of a DNS name for use in a DNS SAN.
// ASCII names pass through unchanged, so existing names — including ones that
// are not strictly valid hostnames — behave exactly as before. Non-ASCII
// (internationalized) names are converted to their A-label (punycode) form,
// the only encoding x509.CreateCertificate accepts for a DNS SAN. A wildcard
// prefix ("*.") is preserved while the remainder of the name is converted.
func dnsNameToASCII(host string) (dnsName string, err error) {
	if isASCII(host) {
		return host, nil
	}

	prefix := ""

	if rest, wildcard := strings.CutPrefix(host, "*."); wildcard {
		prefix, host = "*.", rest
	}

	dnsName, err = idna.Lookup.ToASCII(host)
	if err != nil {
		return "", err
	}

	return prefix + dnsName, nil
}

// isASCII reports whether s contains only ASCII bytes, in which case it is
// already valid for a DNS SAN and needs no A-label conversion.
func isASCII(s string) (isASCII bool) {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}

	return true
}

// New creates a CA from an in-memory CA certificate and
// private key. The certificate must be a CA (IsCA with valid basic
// constraints), and the key must match the certificate's public key. Options
// configure the optional certificate cache.
func New(caCertificate *x509.Certificate, caPrivateKey crypto.Signer, ofs ...OptionFunc) (ca *CA, err error) {
	if caCertificate == nil {
		err = hqgoerrors.New("invalid input, CA certificate is nil")

		return nil, err
	}

	if !caCertificate.IsCA {
		err = hqgoerrors.New("invalid input, certificate is not configured as a CA (IsCA is false)")

		return nil, err
	}

	if !caCertificate.BasicConstraintsValid {
		err = hqgoerrors.New("invalid input, CA certificate's basic constraints are not valid (BasicConstraintsValid is false)")

		return nil, err
	}

	now := time.Now()

	if now.Before(caCertificate.NotBefore) {
		err = hqgoerrors.Errorf("invalid input, CA certificate is not yet valid (NotBefore: %v)", caCertificate.NotBefore)

		return nil, err
	}

	if now.After(caCertificate.NotAfter) {
		err = hqgoerrors.Errorf("invalid input, CA certificate has expired (NotAfter: %v)", caCertificate.NotAfter)

		return nil, err
	}

	if (caCertificate.KeyUsage & x509.KeyUsageCertSign) == 0 {
		err = hqgoerrors.New("invalid input, CA certificate lacks KeyUsageCertSign")

		return nil, err
	}

	if caPrivateKey == nil {
		err = hqgoerrors.New("invalid input, CA private key is nil")

		return nil, err
	}

	switch publicKey := caCertificate.PublicKey.(type) {
	case *rsa.PublicKey:
		privateKey, ok := caPrivateKey.(*rsa.PrivateKey)
		if !ok {
			err = hqgoerrors.Errorf("invalid input, certificate public key is RSA, but private key is %T", caPrivateKey)

			return nil, err
		}

		if !publicKey.Equal(&privateKey.PublicKey) {
			err = hqgoerrors.New("invalid input, CA private key does not match the certificate's public key")

			return nil, err
		}
	case *ecdsa.PublicKey:
		privateKey, ok := caPrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			err = hqgoerrors.Errorf("invalid input, certificate public key is ECDSA, but private key is %T", caPrivateKey)

			return nil, err
		}

		if !publicKey.Equal(&privateKey.PublicKey) {
			err = hqgoerrors.New("invalid input, CA private key does not match the certificate's public key")

			return nil, err
		}
	case ed25519.PublicKey:
		privateKey, ok := caPrivateKey.(ed25519.PrivateKey)
		if !ok {
			err = hqgoerrors.Errorf("invalid input, certificate public key is Ed25519, but private key is %T", caPrivateKey)

			return nil, err
		}

		if !publicKey.Equal(privateKey.Public()) {
			err = hqgoerrors.New("invalid input, CA private key does not match the certificate's public key")

			return nil, err
		}
	default:
		err = hqgoerrors.Errorf("unsupported certificate public key type: %T", publicKey)

		return nil, err
	}

	opts := &Options{
		CacheMaxAge: defaultCacheMaxAge,
	}

	for _, f := range ofs {
		if f == nil {
			continue
		}

		f(opts)
	}

	if opts.CacheMaxAge <= 0 {
		err = hqgoerrors.Errorf("invalid input, cache max age must be positive, got %v", opts.CacheMaxAge)

		return nil, err
	}

	ca = &CA{
		caCertificate:           caCertificate,
		caCertificatePrivateKey: caPrivateKey,
		cache:                   opts.Cache,
		cacheMaxAge:             opts.CacheMaxAge,
		inflight:                make(map[string]*inflightCall),
	}

	return ca, nil
}

// NewFromPEM initializes a new CA from PEM-encoded certificate and private key bytes.
//
// It parses the certificate and private key from the provided byte slices, supporting PKCS#1, PKCS#8, and ECDSA private key formats.
// The parsed certificate and private key are then used to initialize a CA.
//
// The certificate must be in a "CERTIFICATE" PEM block, and the private key in
// an "RSA PRIVATE KEY" (PKCS#1), "EC PRIVATE KEY" (SEC 1), or "PRIVATE KEY"
// (PKCS#8) block. The parsed pair is passed to [New], so all of [New]'s
// validation and options apply.
func NewFromPEM(caCertificateBytes, caPrivateKeyBytes []byte, ofs ...OptionFunc) (ca *CA, err error) {
	if len(caCertificateBytes) == 0 {
		err = hqgoerrors.New("invalid input, CA certificate bytes are empty")

		return nil, err
	}

	if len(caPrivateKeyBytes) == 0 {
		err = hqgoerrors.New("invalid input, CA private key bytes are empty")

		return nil, err
	}

	certBlock, _ := pem.Decode(caCertificateBytes)
	if certBlock == nil {
		err = hqgoerrors.New("decoding PEM block for CA certificate: invalid or malformed PEM data")

		return nil, err
	}

	if certBlock.Type != "CERTIFICATE" {
		err = hqgoerrors.Errorf("invalid PEM block type for CA certificate: got %q, expected 'CERTIFICATE'", certBlock.Type)

		return nil, err
	}

	caCertificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		err = hqgoerrors.Wrap(err, "parsing X.509 certificate from PEM data")

		return nil, err
	}

	keyBlock, _ := pem.Decode(caPrivateKeyBytes)
	if keyBlock == nil {
		err = hqgoerrors.New("decoding PEM block for private key: invalid or malformed PEM data")

		return nil, err
	}

	var caPrivateKey crypto.Signer

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		var key *rsa.PrivateKey

		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			err = hqgoerrors.Wrap(err, "parsing RSA private key from PEM data")

			return nil, err
		}

		caPrivateKey = key
	case "EC PRIVATE KEY":
		var key *ecdsa.PrivateKey

		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			err = hqgoerrors.Wrap(err, "parsing ECDSA private key from PEM data")

			return nil, err
		}

		caPrivateKey = key
	case "PRIVATE KEY":
		var key any

		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			err = hqgoerrors.Wrap(err, "parsing PKCS#8 private key from PEM data")

			return nil, err
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			err = hqgoerrors.Errorf("private key of type %T does not implement crypto.Signer", key)

			return nil, err
		}

		caPrivateKey = signer
	default:
		err = hqgoerrors.Errorf("unsupported PEM block type for private key: got %q, expected 'RSA PRIVATE KEY', 'EC PRIVATE KEY', or 'PRIVATE KEY'", keyBlock.Type)

		return nil, err
	}

	return New(caCertificate, caPrivateKey, ofs...)
}

// GenerateCACertificatePrivateKey generates a new X.509 CA certificate and its corresponding private key.
//
// This function creates a private key (RSA, ECDSA, or Ed25519 based on configuration) and a self-signed CA certificate
// using the functional options pattern. The certificate includes a random serial number, a subject key identifier (SKI),
// and is configured for certificate signing only, with a path length constraint of zero so it can sign end-entity
// certificates but no subordinate CAs. The validity period starts at ValidFrom
// (defaulting to the current time) and extends for ValidFor (defaulting to 365 days). The Common Name has no default
// and must be set with [WithCACommonName]; the Organization is empty unless set with [WithCAOrganization].
func normalizeHost(unnormalized string) (normalized string) {
	// Fast path: with no ':' SplitHostPort always fails, NFC folding and
	// lowering are identity on all-lowercase ASCII, and there is no trailing
	// dot to strip, so the host is already normalized.
	if strings.IndexByte(unnormalized, ':') < 0 && isLowercaseASCII(unnormalized) && !strings.HasSuffix(unnormalized, ".") {
		return unnormalized
	}

	normalized = unnormalized

	if host, _, err := net.SplitHostPort(unnormalized); err == nil {
		normalized = host
	}

	normalized = strings.TrimSuffix(strings.ToLower(norm.NFC.String(normalized)), ".")

	return normalized
}

// isLowercaseASCII reports whether s contains only ASCII bytes and no uppercase
// letters, in which case NFC folding and lowering cannot change it.
func isLowercaseASCII(s string) (isLower bool) {
	for i := range len(s) {
		c := s[i]
		if c >= utf8.RuneSelf || (c >= 'A' && c <= 'Z') {
			return false
		}
	}

	return true
}

// operations bundles the cryptographic, parsing, and filesystem calls the
// package makes. Production code uses the implementations returned by
// [defaultOperations]; tests replace individual fields to exercise failure
// paths that the underlying standard library call cannot produce on demand.
//
// A nil [CA.ops] means the default operations.
//
// Fields:
//   - rsaGenerateKey: RSA key generation ([rsa.GenerateKey]).
//   - ecdsaGenerateKey: ECDSA key generation ([ecdsa.GenerateKey]).
//   - ed25519GenerateKey: Ed25519 key generation ([ed25519.GenerateKey]).
//   - randomInt: cryptographic random integer ([crypto/rand.Int]).
//   - marshalPKIXPublicKey: PKIX public key marshaling
//     ([x509.MarshalPKIXPublicKey]).
//   - marshalPKCS8Key: PKCS#8 private key marshaling
//     ([x509.MarshalPKCS8PrivateKey]).
//   - createCertificate: certificate creation ([x509.CreateCertificate]).
//   - parseCertificate: certificate parsing ([x509.ParseCertificate]).
//   - loadKeyPair: PEM key-pair loading ([tls.LoadX509KeyPair]).
//   - lstat: symlink-safe file inspection ([os.Lstat]).
//   - chmodBeforeWrite: permission change before writing ([os.Chmod]).
//   - chmodAfterWrite: permission change after writing ([os.Chmod]).
//   - certificateToPEM: certificate PEM encoding ([CertificateToPEM]).
//   - privateKeyToPEM: private key PEM encoding ([PrivateKeyToPEM]).
