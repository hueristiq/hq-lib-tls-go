package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"time"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// GenerateCACertificatePrivateKey generates a self-signed CA certificate and
// its private key, configured by the CA options (CommonName is required).
// Use [CertificateToPEM] and [PrivateKeyToPEM] to persist them, or
// [GenerateCACertificatePrivateKeyPEM] for the PEM form directly.
func GenerateCACertificatePrivateKey(ofs ...CAOptionFunc) (certificate *x509.Certificate, privateKey crypto.Signer, err error) {
	return generateCACertificatePrivateKey(defaultOperations(), ofs...)
}

// generateCACertificatePrivateKey generates a self-signed CA certificate and
// its private key using the given operations.
func generateCACertificatePrivateKey(ops *operations, ofs ...CAOptionFunc) (certificate *x509.Certificate, privateKey crypto.Signer, err error) {
	opts := &CAOptions{
		ValidFrom: time.Now(),
		ValidFor:  365 * 24 * time.Hour,
	}

	for _, f := range ofs {
		if f == nil {
			continue
		}

		f(opts)
	}

	if opts.CommonName == "" {
		err = hqgoerrors.New("invalid input, CommonName is empty")

		return nil, nil, err
	}

	if err := validateValidFor(opts.ValidFor); err != nil {
		return nil, nil, err
	}

	switch opts.KeyType {
	case KeyTypeRSA2048:
		privateKey, err = ops.rsaGenerateKey(rand.Reader, 2048)
		if err != nil {
			err = hqgoerrors.Wrap(err, "generating RSA private key (2048 bits)")

			return nil, nil, err
		}
	case KeyTypeECDSAP256:
		privateKey, err = ops.ecdsaGenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			err = hqgoerrors.Wrap(err, "generating ECDSA private key (curve P-256)")

			return nil, nil, err
		}
	case KeyTypeEd25519:
		_, privateKey, err = ops.ed25519GenerateKey(rand.Reader)
		if err != nil {
			err = hqgoerrors.Wrap(err, "generating Ed25519 private key")

			return nil, nil, err
		}
	default:
		err = hqgoerrors.Errorf("invalid input, unsupported CA key type: %d", opts.KeyType)

		return nil, nil, err
	}

	publicKey := privateKey.Public()

	serialNumber, err := generateSerialNumberWith(ops)
	if err != nil {
		err = hqgoerrors.Wrap(err, "generating serial number for CA certificate")

		return nil, nil, err
	}

	subjectKeyID, err := generateSubjectKeyIDWith(ops, publicKey)
	if err != nil {
		err = hqgoerrors.Wrapf(err, "generating subject key ID for public key (type %T)", publicKey)

		return nil, nil, err
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Constrain the CA to signing end-entity certificates: no subordinate
		// CAs, and no CRL signing since this package never issues CRLs.
		MaxPathLenZero: true,
		KeyUsage:       x509.KeyUsageCertSign,
		// Backdate NotBefore by 5 minutes to tolerate modest clock skew between
		// this host and verifying clients.
		NotBefore:    opts.ValidFrom.Add(-5 * time.Minute),
		NotAfter:     opts.ValidFrom.Add(opts.ValidFor),
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: opts.Organization,
		},
		SubjectKeyId: subjectKeyID,
	}

	certificateDER, err := ops.createCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "creating self-signed CA certificate")

		return nil, nil, err
	}

	certificate, err = ops.parseCertificate(certificateDER)
	if err != nil {
		err = hqgoerrors.Wrap(err, "parsing generated CA certificate")

		return nil, nil, err
	}

	return certificate, privateKey, nil
}

// GenerateCACertificatePrivateKeyPEM generates a new X.509 CA certificate and private key, returning them in PEM format.
//
// This function wraps [GenerateCACertificatePrivateKey] and converts the resulting certificate and private key to PEM format.
//
// A Common Name option is required, as documented for
// [GenerateCACertificatePrivateKey]. The certificate is encoded in a
// "CERTIFICATE" block; the private key block type depends on the key
// algorithm: "RSA PRIVATE KEY" for RSA, "EC PRIVATE KEY" for ECDSA, and
// "PRIVATE KEY" (PKCS#8) for Ed25519.
func GenerateCACertificatePrivateKeyPEM(ofs ...CAOptionFunc) (certificateBytes, privateKeyBytes []byte, err error) {
	return generateCACertificatePrivateKeyPEM(defaultOperations(), ofs...)
}

// generateCACertificatePrivateKeyPEM generates a CA certificate and private
// key and encodes both as PEM using the given operations.
func generateCACertificatePrivateKeyPEM(ops *operations, ofs ...CAOptionFunc) (certificateBytes, privateKeyBytes []byte, err error) {
	certificate, privateKey, err := generateCACertificatePrivateKey(ops, ofs...)
	if err != nil {
		err = hqgoerrors.Wrap(err, "generating CA certificate and private key")

		return nil, nil, err
	}

	certificateBytes, err = ops.certificateToPEM(certificate)
	if err != nil {
		err = hqgoerrors.Wrap(err, "converting CA certificate to PEM format")

		return nil, nil, err
	}

	privateKeyBytes, err = ops.privateKeyToPEM(privateKey)
	if err != nil {
		err = hqgoerrors.Wrapf(err, "converting CA private key to PEM format (type %T)", privateKey)

		return nil, nil, err
	}

	return certificateBytes, privateKeyBytes, nil
}

// CertificateToPEM converts an X.509 certificate to PEM format.
//
// The certificate is encoded as a PEM block with type "CERTIFICATE", as per [RFC 7468](https://www.rfc-editor.org/info/rfc7468/). The resulting PEM data
// is returned as a byte slice for further use (e.g., writing to a file or network).
func CertificateToPEM(certificate *x509.Certificate) (raw []byte, err error) {
	if certificate == nil {
		err = hqgoerrors.New("invalid input, certificate is nil")

		return nil, err
	}

	if len(certificate.Raw) == 0 {
		err = hqgoerrors.New("invalid input, certificate raw data is empty")

		return nil, err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	}

	return pem.EncodeToMemory(block), nil
}

// PrivateKeyToPEM converts a private key to PEM format.
//
// The private key is marshaled to the appropriate format (PKCS#1 for RSA, EC for ECDSA, PKCS#8 for Ed25519) and encoded
// as a PEM block with type "RSA PRIVATE KEY", "EC PRIVATE KEY", or "PRIVATE KEY", as per [RFC 7468](https://www.rfc-editor.org/info/rfc7468/). The resulting PEM data
// is returned as a byte slice.
func PrivateKeyToPEM(key crypto.Signer) (raw []byte, err error) {
	return privateKeyToPEM(defaultOperations(), key)
}

// privateKeyToPEM converts a private key to PEM format using the given
// operations.
func privateKeyToPEM(ops *operations, key crypto.Signer) (raw []byte, err error) {
	if key == nil {
		err = hqgoerrors.New("invalid input, private key is nil")

		return nil, err
	}

	var blockType string

	var keyBytes []byte

	switch k := key.(type) {
	case *rsa.PrivateKey:
		blockType = "RSA PRIVATE KEY"
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		blockType = "EC PRIVATE KEY"

		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			err = hqgoerrors.Wrap(err, "marshaling ECDSA private key")

			return nil, err
		}
	case ed25519.PrivateKey:
		blockType = "PRIVATE KEY"

		keyBytes, err = ops.marshalPKCS8Key(k)
		if err != nil {
			err = hqgoerrors.Wrap(err, "marshaling Ed25519 private key")

			return nil, err
		}
	default:
		err = hqgoerrors.Errorf("unsupported private key type: %T", key)

		return nil, err
	}

	block := &pem.Block{
		Type:  blockType,
		Bytes: keyBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// serialNumberLimit is the exclusive upper bound for generated certificate
// serial numbers (2^128). crypto/rand.Int does not mutate max, so a single
// shared value is safe for concurrent use.
var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// generateSerialNumber creates a random serial number for use in X.509 certificates.
//
// Serial numbers are unique identifiers for certificates, and [RFC 5280](https://www.rfc-editor.org/info/rfc5280/) requires them to be
// positive integers. This function generates a cryptographically secure random number with a
// maximum bit length of 128 bits, redrawing until the value is strictly positive, ensuring
// compliance with common certificate authority requirements.
func generateSerialNumber() (serialNumber *big.Int, err error) {
	return generateSerialNumberWith(defaultOperations())
}

// generateSerialNumberWith creates a random serial number using the given
// operations.
func generateSerialNumberWith(ops *operations) (serialNumber *big.Int, err error) {
	// rand.Int may return zero, but [RFC 5280](https://www.rfc-editor.org/info/rfc5280/) requires a positive serial number:
	// redraw until the value is strictly positive.
	for serialNumber == nil || serialNumber.Sign() <= 0 {
		serialNumber, err = ops.randomInt(rand.Reader, serialNumberLimit)
		if err != nil {
			err = hqgoerrors.Wrap(err, "generating random serial number (128-bit)")

			return nil, err
		}
	}

	return serialNumber, nil
}

// generateSubjectKeyID computes a Subject Key Identifier (SKI) from a given public key.
//
// The Subject Key Identifier is a SHA-256 hash of the public key's PKIX-encoded form, as specified in [RFC 5280](https://www.rfc-editor.org/info/rfc5280/),
// section 4.2.1.2. It is used to uniquely identify a public key in an X.509 certificate.
func generateSubjectKeyID(publicKey crypto.PublicKey) (ski []byte, err error) {
	return generateSubjectKeyIDWith(defaultOperations(), publicKey)
}

// generateSubjectKeyIDWith computes a Subject Key Identifier using the given
// operations.
func generateSubjectKeyIDWith(ops *operations, publicKey crypto.PublicKey) (ski []byte, err error) {
	if publicKey == nil {
		err = hqgoerrors.New("invalid input, public key is nil")

		return nil, err
	}

	pkixPub, err := ops.marshalPKIXPublicKey(publicKey)
	if err != nil {
		err = hqgoerrors.Wrapf(err, "marshaling public key (type %T) to PKIX format", publicKey)

		return nil, err
	}

	if len(pkixPub) == 0 {
		err = hqgoerrors.Errorf("invalid public key (type %T), marshaled PKIX data is empty", publicKey)

		return nil, err
	}

	sum := sha256.Sum256(pkixPub)

	return sum[:], nil
}

// validateValidFor returns an error when a configured validity duration is not
// positive. It is shared by CA generation, leaf issuance, and CSR signing.
func validateValidFor(validFor time.Duration) (err error) {
	if validFor <= 0 {
		err = hqgoerrors.Errorf("invalid input, ValidFor duration must be positive, got %v", validFor)

		return err
	}

	return nil
}

type operations struct {
	rsaGenerateKey       func(io.Reader, int) (*rsa.PrivateKey, error)
	ecdsaGenerateKey     func(elliptic.Curve, io.Reader) (*ecdsa.PrivateKey, error)
	ed25519GenerateKey   func(io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error)
	randomInt            func(io.Reader, *big.Int) (*big.Int, error)
	marshalPKIXPublicKey func(any) ([]byte, error)
	marshalPKCS8Key      func(any) ([]byte, error)
	createCertificate    func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error)
	parseCertificate     func([]byte) (*x509.Certificate, error)
	loadKeyPair          func(string, string) (tls.Certificate, error)
	lstat                func(string) (os.FileInfo, error)
	chmodBeforeWrite     func(string, os.FileMode) error
	chmodAfterWrite      func(string, os.FileMode) error
	certificateToPEM     func(*x509.Certificate) ([]byte, error)
	privateKeyToPEM      func(crypto.Signer) ([]byte, error)
}

// defaultOperations returns the production operation set.
func defaultOperations() (ops *operations) {
	ops = &operations{
		rsaGenerateKey:       rsa.GenerateKey,
		ecdsaGenerateKey:     ecdsa.GenerateKey,
		ed25519GenerateKey:   ed25519.GenerateKey,
		randomInt:            rand.Int,
		marshalPKIXPublicKey: x509.MarshalPKIXPublicKey,
		marshalPKCS8Key:      x509.MarshalPKCS8PrivateKey,
		createCertificate:    x509.CreateCertificate,
		parseCertificate:     x509.ParseCertificate,
		loadKeyPair:          tls.LoadX509KeyPair,
		lstat:                os.Lstat,
		chmodBeforeWrite:     os.Chmod,
		chmodAfterWrite:      os.Chmod,
		certificateToPEM:     CertificateToPEM,
	}

	ops.privateKeyToPEM = func(key crypto.Signer) ([]byte, error) {
		return privateKeyToPEM(ops, key)
	}

	return ops
}

// operations returns the operation set the authority was configured with,
// falling back to [defaultOperations].
func (ca *CertificateAuthority) operations() (ops *operations) {
	if ca != nil && ca.ops != nil {
		return ca.ops
	}

	return defaultOperations()
}
