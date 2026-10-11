package probe

import (
	"crypto/tls"
	"fmt"
	"time"
)

const (
	// defaultMode is the connection mode used when [WithMode] is not given.
	defaultMode = ModeAuto
	// defaultTimeout is the per-connection timeout used when [WithTimeout]
	// is not given.
	defaultTimeout = 5 * time.Second
	// defaultOpenSSLBinary is the OpenSSL binary used by [ModeOpenSSL]
	// when [WithOpenSSLBinary] is not given.
	defaultOpenSSLBinary = "openssl"
	// sslVersion30 is the SSL 3.0 version ID. crypto/tls's exported
	// constant is deprecated, but the prober must still recognize the ID
	// when it is offered as a minimum or maximum version.
	sslVersion30 = 0x0300
)

// options defines the configuration of a [Prober]. Unset fields fall back
// to the default* constants and are validated by [New].
//
// Fields:
//   - Mode (Mode): the TLS connection mode.
//   - Timeout (time.Duration): the per-connection timeout.
//   - ServerName (string): the SNI name to send; when empty, the probed
//     host is used.
//   - CipherSuites ([]uint16): the cipher suites to offer; when empty, the
//     dialing library's default set is used.
//   - MinVersion (uint16): the minimum TLS version to offer; zero keeps the
//     library default.
//   - MaxVersion (uint16): the maximum TLS version to offer; zero keeps the
//     library default.
//   - NextProtos ([]string): the ALPN protocols to advertise.
//   - PreHandshake (bool): abort the zcrypto handshake as soon as the
//     ServerHello and certificates are captured, skipping the client's
//     key exchange (effective for TLS 1.2 and below).
//   - Proxy (string): a SOCKS5 proxy address (host:port); empty disables
//     proxying.
//   - OpenSSLBinary (string): the OpenSSL binary used by [ModeOpenSSL].
type options struct {
	Mode          Mode
	Timeout       time.Duration
	ServerName    string
	CipherSuites  []uint16
	MinVersion    uint16
	MaxVersion    uint16
	NextProtos    []string
	PreHandshake  bool
	Proxy         string
	OpenSSLBinary string
}

// Option is a function type used to configure a [Prober] created by [New]
// using the functional options pattern. Options are applied in order, so
// later options override earlier ones.
//
// Parameters:
//   - opts (*options): a pointer to options to be modified.
type Option func(opts *options)

// WithMode sets the TLS connection mode.
//
// The default is [ModeAuto].
//
// Parameters:
//   - mode (Mode): the connection mode to use ([ModeAuto], [ModeCTLS],
//     [ModeZTLS], or [ModeOpenSSL]).
//
// Returns:
//   - of (Option): an Option that updates the Mode field of the options.
func WithMode(mode Mode) (of Option) {
	return func(opts *options) {
		opts.Mode = mode
	}
}

// WithTimeout sets the per-connection timeout: dialing, the handshake, and
// reading the server's first response are all bounded by it.
//
// The default is 5 seconds, and the timeout must be positive: [New] returns
// an error otherwise.
//
// Parameters:
//   - timeout (time.Duration): the connection timeout (e.g., 5*time.Second).
//
// Returns:
//   - of (Option): an Option that updates the Timeout field of the options.
func WithTimeout(timeout time.Duration) (of Option) {
	return func(opts *options) {
		opts.Timeout = timeout
	}
}

// WithServerName sets the Server Name Indication (SNI) name sent in the
// ClientHello.
//
// When unset, the probed host is used. This is useful when probing by IP
// while presenting a hostname, or for virtual-host discovery.
//
// Parameters:
//   - serverName (string): the SNI name to send (e.g., "example.com").
//
// Returns:
//   - of (Option): an Option that updates the ServerName field of the options.
func WithServerName(serverName string) (of Option) {
	return func(opts *options) {
		opts.ServerName = serverName
	}
}

// WithCipherSuites sets the cipher suites offered in the ClientHello.
//
// When unset, the dialing library's default set is used. Restricting the
// list enables cipher-suite enumeration: probe once per suite and read the
// negotiated [Result.CipherSuite].
//
// Parameters:
//   - cipherSuites ([]uint16): the cipher suite IDs to offer.
//
// Returns:
//   - of (Option): an Option that updates the CipherSuites field of the options.
func WithCipherSuites(cipherSuites []uint16) (of Option) {
	return func(opts *options) {
		opts.CipherSuites = cipherSuites
	}
}

// WithMinVersion sets the minimum TLS version offered in the ClientHello.
//
// When zero, the dialing library's default applies.
//
// Parameters:
//   - minVersion (uint16): the minimum version (e.g., [tls.VersionTLS12]).
//
// Returns:
//   - of (Option): an Option that updates the MinVersion field of the options.
func WithMinVersion(minVersion uint16) (of Option) {
	return func(opts *options) {
		opts.MinVersion = minVersion
	}
}

// WithMaxVersion sets the maximum TLS version offered in the ClientHello.
//
// When zero, the dialing library's default applies.
//
// Parameters:
//   - maxVersion (uint16): the maximum version (e.g., [tls.VersionTLS13]).
//
// Returns:
//   - of (Option): an Option that updates the MaxVersion field of the options.
func WithMaxVersion(maxVersion uint16) (of Option) {
	return func(opts *options) {
		opts.MaxVersion = maxVersion
	}
}

// WithNextProtos sets the ALPN protocols advertised in the ClientHello.
//
// The default is the dialing library's default set.
//
// Parameters:
//   - nextProtos (...string): the ALPN protocol identifiers, in preference order.
//
// Returns:
//   - of (Option): an Option that updates the NextProtos field of the options.
func WithNextProtos(nextProtos ...string) (of Option) {
	return func(opts *options) {
		opts.NextProtos = nextProtos
	}
}

// WithPreHandshake enables early termination of the zcrypto handshake: the
// connection is closed as soon as the ServerHello and server certificates
// are captured, before the client's key exchange completes. This makes
// certificate gathering faster and lighter on the server.
//
// Pre-handshake applies to [ModeZTLS] and [ModeAuto] only and is effective
// for TLS 1.2 and below; TLS 1.3 completes normally.
//
// Parameters:
//   - enabled (bool): whether to terminate the handshake early.
//
// Returns:
//   - of (Option): an Option that updates the PreHandshake field of the options.
func WithPreHandshake(enabled bool) (of Option) {
	return func(opts *options) {
		opts.PreHandshake = enabled
	}
}

// WithProxy sets a SOCKS5 proxy for the connection.
//
// The proxy is used by the zcrypto, crypto/tls, and JARM connections alike.
//
// Parameters:
//   - proxyAddress (string): the SOCKS5 proxy address (e.g., "127.0.0.1:9050").
//
// Returns:
//   - of (Option): an Option that updates the Proxy field of the options.
func WithProxy(proxyAddress string) (of Option) {
	return func(opts *options) {
		opts.Proxy = proxyAddress
	}
}

// WithOpenSSLBinary sets the OpenSSL binary used by [ModeOpenSSL].
//
// The default is "openssl", resolved through PATH.
//
// Parameters:
//   - path (string): the OpenSSL binary path or name.
//
// Returns:
//   - of (Option): an Option that updates the OpenSSLBinary field of the options.
func WithOpenSSLBinary(path string) (of Option) {
	return func(opts *options) {
		opts.OpenSSLBinary = path
	}
}

// validateVersion reports whether version is a recognized TLS version or
// zero (library default).
func validateVersion(version uint16) (valid bool) {
	switch version {
	case 0, sslVersion30, tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13:
		valid = true
	}

	return valid
}

// validate normalizes the options and reports the first invalid value.
//
// Returns:
//   - err (error): non-nil when a value is invalid; otherwise, nil.
func (opts *options) validate() (err error) {
	if opts.Timeout <= 0 {
		err = fmt.Errorf("probe: invalid input, timeout must be positive, got %v", opts.Timeout)

		return err
	}

	if !validateVersion(opts.MinVersion) {
		err = fmt.Errorf("probe: invalid input, unrecognized minimum TLS version: %#x", opts.MinVersion)

		return err
	}

	if !validateVersion(opts.MaxVersion) {
		err = fmt.Errorf("probe: invalid input, unrecognized maximum TLS version: %#x", opts.MaxVersion)

		return err
	}

	if opts.MinVersion != 0 && opts.MaxVersion != 0 && opts.MinVersion > opts.MaxVersion {
		err = fmt.Errorf("probe: invalid input, minimum TLS version %#x exceeds maximum %#x", opts.MinVersion, opts.MaxVersion)

		return err
	}

	return nil
}
