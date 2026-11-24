package client

import (
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"io"
	"slices"
	"time"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

// Certificate is compatible with crypto/tls.Certificate, so certificates
// loaded with LoadX509KeyPair or crypto/tls.LoadX509KeyPair work unchanged.
type Certificate = stdtls.Certificate

// CurveID is compatible with crypto/tls.CurveID.
type CurveID = stdtls.CurveID

// SignatureScheme is compatible with crypto/tls.SignatureScheme.
type SignatureScheme = stdtls.SignatureScheme

// CertificateRequestInfo carries the server's client-certificate request.
type CertificateRequestInfo struct {
	AcceptableCAs    [][]byte
	SignatureSchemes []SignatureScheme
	Version          uint16
}

// Config configures a client connection. Field names follow crypto/tls so
// existing TLS configuration knowledge transfers directly, with additional
// fields for legacy protocols, ClientHello construction, and handshake
// capture.
type Config struct {
	// Rand supplies entropy. Nil uses crypto/rand.
	Rand io.Reader
	// Time supplies the current time. Nil uses time.Now.
	Time func() time.Time

	// ServerName is sent as SNI and used for certificate verification unless
	// InsecureSkipVerify is set.
	ServerName string
	// InsecureSkipVerify disables chain and hostname verification.
	InsecureSkipVerify bool
	// RootCAs is the trust store. Nil uses the system roots.
	RootCAs *x509.CertPool
	// Certificates are the client certificates offered to servers.
	Certificates []Certificate
	// GetClientCertificate selects a client certificate dynamically.
	GetClientCertificate func(*CertificateRequestInfo) (*Certificate, error)
	// NextProtos lists the ALPN protocols to advertise.
	NextProtos []string
	// CipherSuites lists the suites to offer. Nil uses the default set.
	CipherSuites []uint16
	// MinVersion is the lowest protocol version to offer. Zero defaults to
	// TLS 1.2.
	MinVersion uint16
	// MaxVersion is the highest protocol version to offer. Zero defaults to
	// TLS 1.3.
	MaxVersion uint16
	// CurvePreferences lists the supported groups in preference order.
	CurvePreferences []CurveID
	// KeyShareGroups lists the groups to send key shares for. Nil uses
	// CurvePreferences (or the default groups).
	KeyShareGroups []CurveID
	// SignatureAlgorithms lists the signature schemes to advertise.
	SignatureAlgorithms []SignatureScheme

	// VerifyPeerCertificate runs after the normal chain verification, or in
	// place of it when InsecureSkipVerify is set.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	// VerifyConnection runs after verification and after VerifyPeerCertificate.
	VerifyConnection func(ConnectionState) error
	// KeyLogWriter receives NSS key-log lines for the connection.
	KeyLogWriter io.Writer

	// ClientHelloSpec, when non-nil, is used verbatim as the ClientHello.
	ClientHelloSpec *HelloSpec
	// HandshakeLogger receives each decrypted handshake message as it occurs.
	HandshakeLogger func(HandshakeEvent)
	// HandshakeTraceLimit bounds the bytes of Raw retained in the trace. Zero
	// uses 4 MiB; a negative value keeps every message.
	HandshakeTraceLimit int
	// RecordFragmentation splits handshake writes into records of this size.
	// Zero disables fragmentation.
	RecordFragmentation int
	// AllowExportCipherSuites permits export-grade suites in CipherSuites.
	AllowExportCipherSuites bool
	// MinDHBits rejects DHE parameters smaller than this. Zero disables the
	// check, which is required for 512-bit export groups.
	MinDHBits int
}

// Clone returns a deep copy of the configuration.
func (c *Config) Clone() (clone *Config) {
	if c == nil {
		return nil
	}

	clone = &Config{}
	*clone = *c
	clone.Certificates = append([]Certificate(nil), c.Certificates...)
	clone.NextProtos = append([]string(nil), c.NextProtos...)
	clone.CipherSuites = append([]uint16(nil), c.CipherSuites...)
	clone.CurvePreferences = append([]CurveID(nil), c.CurvePreferences...)
	clone.KeyShareGroups = append([]CurveID(nil), c.KeyShareGroups...)
	clone.SignatureAlgorithms = append([]SignatureScheme(nil), c.SignatureAlgorithms...)

	if c.ClientHelloSpec != nil {
		spec := *c.ClientHelloSpec
		spec.CipherSuites = append([]uint16(nil), c.ClientHelloSpec.CipherSuites...)
		spec.CompressionMethods = append([]uint8(nil), c.ClientHelloSpec.CompressionMethods...)
		spec.Extensions = append([]Extension(nil), c.ClientHelloSpec.Extensions...)
		clone.ClientHelloSpec = &spec
	}

	return clone
}

// Validate normalizes defaults and reports the first invalid setting.
func (c *Config) Validate() (err error) {
	if c.MinVersion == 0 {
		c.MinVersion = VersionTLS12
	}

	if c.MaxVersion == 0 {
		c.MaxVersion = VersionTLS13
	}

	if !validVersion(c.MinVersion) {
		err = hqgoerrors.Errorf("%w: %#x", ErrUnsupportedVersion, c.MinVersion)

		return err
	}

	if !validVersion(c.MaxVersion) {
		err = hqgoerrors.Errorf("%w: %#x", ErrUnsupportedVersion, c.MaxVersion)

		return err
	}

	if c.MinVersion > c.MaxVersion {
		err = hqgoerrors.Errorf("invalid input, minimum TLS version %#x exceeds maximum %#x", c.MinVersion, c.MaxVersion)

		return err
	}

	if len(c.CipherSuites) == 0 {
		c.CipherSuites = defaultCipherSuites(c.MinVersion, c.MaxVersion)
	}

	for _, id := range c.CipherSuites {
		if hqgotlsciphers.IsExport(id) && !c.AllowExportCipherSuites {
			err = hqgoerrors.Errorf("%w: %s", ErrExportCipherSuitesDisabled, hqgotlsciphers.Name(id))

			return err
		}
	}

	if len(c.KeyShareGroups) > 0 && len(c.CurvePreferences) > 0 {
		for _, group := range c.KeyShareGroups {
			if !slices.Contains(c.CurvePreferences, group) {
				err = hqgoerrors.Errorf("invalid input, key share group %#x is not in CurvePreferences", uint16(group))

				return err
			}
		}
	}

	if c.RecordFragmentation != 0 && c.RecordFragmentation < 128 {
		err = hqgoerrors.Errorf("invalid input, record fragmentation must be at least 128 bytes, got %d", c.RecordFragmentation)

		return err
	}

	if c.MinDHBits < 0 {
		err = hqgoerrors.Errorf("invalid input, minimum DH bits must not be negative, got %d", c.MinDHBits)

		return err
	}

	if c.ClientHelloSpec != nil {
		if err := c.ClientHelloSpec.validate(); err != nil {
			return err
		}

		if c.ClientHelloSpec.TLSVersMin < c.MinVersion || c.ClientHelloSpec.TLSVersMax > c.MaxVersion {
			err = hqgoerrors.Errorf("%w: spec version range %#x-%#x is outside the configured range %#x-%#x", ErrInvalidClientHelloSpec, c.ClientHelloSpec.TLSVersMin, c.ClientHelloSpec.TLSVersMax, c.MinVersion, c.MaxVersion)

			return err
		}

		for _, id := range c.ClientHelloSpec.CipherSuites {
			if hqgotlsciphers.IsExport(id) && !c.AllowExportCipherSuites {
				err = hqgoerrors.Errorf("%w: %s", ErrExportCipherSuitesDisabled, hqgotlsciphers.Name(id))

				return err
			}
		}
	}

	return nil
}

// randReader returns the configured entropy source.
func (c *Config) randReader() (reader io.Reader) {
	if c.Rand != nil {
		return c.Rand
	}

	return rand.Reader
}

// now returns the configured clock.
func (c *Config) now() (now time.Time) {
	if c.Time != nil {
		return c.Time()
	}

	return time.Now()
}

// supportsVersion reports whether version lies within the configured range.
func (c *Config) supportsVersion(version uint16) (supported bool) {
	return version >= c.MinVersion && version <= c.MaxVersion
}

// defaultCipherSuites returns the default suite list for the version range.
// Modern ranges get secure suites; legacy ranges also get the non-export weak
// and insecure suites needed to talk to old servers.
func defaultCipherSuites(minVersion, maxVersion uint16) (ids []uint16) {
	seen := make(map[uint16]struct{})

	add := func(suite hqgotlsciphers.Suite) {
		if _, ok := seen[suite.ID]; ok {
			return
		}

		supported := false

		for _, version := range suite.Versions {
			if version >= minVersion && version <= maxVersion {
				supported = true

				break
			}
		}

		if !supported {
			return
		}

		seen[suite.ID] = struct{}{}

		ids = append(ids, suite.ID)
	}

	implemented := hqgotlsciphers.Implemented()

	for i := range implemented {
		suite := &implemented[i]

		if suite.Export {
			continue
		}

		switch {
		case suite.Security >= hqgotlsciphers.SecuritySecure:
			add(*suite)
		case minVersion <= VersionTLS11 && suite.Security >= hqgotlsciphers.SecurityWeak:
			add(*suite)
		case minVersion == VersionSSL30:
			add(*suite)
		}
	}

	return ids
}

// LoadX509KeyPair loads a certificate and private key from PEM files.
func LoadX509KeyPair(certFile, keyFile string) (certificate Certificate, err error) {
	certificate, err = stdtls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		err = hqgoerrors.Wrap(err, "loading X.509 key pair")

		return certificate, err
	}

	return certificate, nil
}

// X509KeyPair parses a certificate and private key from PEM blocks.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (certificate Certificate, err error) {
	certificate, err = stdtls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		err = hqgoerrors.Wrap(err, "parsing X.509 key pair")

		return certificate, err
	}

	return certificate, nil
}

// hasSuite reports whether ids contains id.
func hasSuite(ids []uint16, id uint16) (found bool) {
	return slices.Contains(ids, id)
}
