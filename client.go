package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

const (
	// defaultPort is appended to hosts given without a port.
	defaultPort = "443"
)

// A Client connects to TLS servers and captures what they offer. It is
// immutable after construction and safe for concurrent use: [Inspect] and
// [JARM] open independent connections per call.
//
// Fields:
//   - options (Options): the resolved connection configuration.
//   - dialer (proxy.ContextDialer): the dialer used for every connection,
//     wrapping the SOCKS5 proxy when one is configured.
type Client struct {
	options Options
	dialer  proxy.ContextDialer
}

// New creates a Client. Unset options fall back to their defaults, and
// invalid values are rejected.
//
// Parameters:
//   - ofs (...OptionFunc): a variadic list of OptionFunc functions to configure
//     the client (e.g., [WithMode], [WithTimeout]).
//
// Returns:
//   - client (*Client): the initialized client.
//   - err (error): an error if an option value is invalid; otherwise, nil.
func New(ofs ...OptionFunc) (client *Client, err error) {
	opts := &Options{
		Mode:          defaultMode,
		Timeout:       defaultTimeout,
		OpenSSLBinary: defaultOpenSSLBinary,
	}

	for _, f := range ofs {
		if f == nil {
			continue
		}

		f(opts)
	}

	if err = opts.validate(); err != nil {
		err = fmt.Errorf("client.New: %w", err)

		return nil, err
	}

	client = &Client{
		options: *opts,
		dialer:  proxy.Direct,
	}

	if opts.Proxy != "" {
		// proxy.SOCKS5 builds the dialer without I/O and cannot fail for the
		// tcp network; its concrete type always implements ContextDialer.
		socks5, _ := proxy.SOCKS5("tcp", opts.Proxy, nil, proxy.Direct)

		client.dialer = socks5.(proxy.ContextDialer)
	}

	return client, nil
}

// Inspect connects to host and captures the negotiated parameters,
// certificates, and handshake messages according to the configured mode.
//
// The host may be given with or without a port; without one, 443 is used.
// Dialing failures (unreachable host, connection refused, exhausted
// context) are returned as err; a reached server whose handshake fails
// yields a result carrying [Result.Error] instead, so callers can still
// report inspection status.
//
// Parameters:
//   - ctx (context.Context): the context bounding the whole operation.
//   - host (string): the target, as hostname, IP, "host:port", or "IP:port".
//
// Returns:
//   - result (Result): the inspection outcome; valid even when the handshake failed.
//   - err (error): non-nil only when no connection could be established.
func (p *Client) Inspect(ctx context.Context, host string) (result Result, err error) {
	host, port, err := splitHostPort(host)
	if err != nil {
		err = fmt.Errorf("client.Inspect: %w", err)

		return Result{}, err
	}

	address := net.JoinHostPort(host, port)

	switch p.options.Mode {
	case ModeAuto:
		result, err = p.inspectWithAuto(ctx, host, address)
	case ModeCTLS:
		result, err = p.inspectWithCTLS(ctx, host, address)
	case ModeZTLS:
		result, err = p.inspectWithZTLS(ctx, host, address)
	case ModeOpenSSL:
		result, err = p.inspectWithOpenSSL(ctx, host, address)
	default:
		// Out-of-range modes behave as auto, like the zero value.
		result, err = p.inspectWithAuto(ctx, host, address)
	}

	if err != nil {
		err = fmt.Errorf("client.Inspect: inspecting %s: %w", host, err)

		return Result{}, err
	}

	result.Host = host

	return result, nil
}

// splitHostPort splits host into its hostname and port parts, defaulting
// the port to 443 when absent. IPv6 literals must be bracketed, as in
// net.JoinHostPort's syntax. A present port is passed through unchanged; the
// dialer reports an unusable value.
//
// Parameters:
//   - host (string): the target as given by the caller.
//
// Returns:
//   - hostname (string): the host without port.
//   - port (string): the port as given, or 443 when absent.
//   - err (error): non-nil when the input is empty.
func splitHostPort(host string) (hostname, port string, err error) {
	if host == "" {
		err = errors.New("client.splitHostPort: invalid input, host is empty")

		return "", "", err
	}

	hostname, port, err = net.SplitHostPort(host)
	if err != nil {
		// Every split failure (missing port, bare IPv6 literal, too many
		// colons) yields empty parts; treat the whole input as the hostname
		// with the default port.
		hostname, port = host, defaultPort
	}

	return hostname, port, nil
}

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
	// constant is deprecated, but the client must still recognize the ID
	// when it is offered as a minimum or maximum version.
	sslVersion30 = 0x0300
)

// Options defines the configuration of a [Client]. Unset fields fall back
// to the default* constants and are validated by [New].
//
// Fields:
//   - Mode (Mode): the TLS connection mode.
//   - Timeout (time.Duration): the per-connection timeout.
//   - ServerName (string): the SNI name to send; when empty, the inspected
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
type Options struct {
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

// OptionFunc configures a [Client] created by [New]. A nil OptionFunc is ignored.
// Options are applied in order, so later options override earlier ones. The
// With* helpers cover common settings, and callers may write custom options
// because [Options] is exported.
//
// Parameters:
//   - opts (*Options): the options to modify.
type OptionFunc func(opts *Options)

// WithMode sets the TLS connection mode.
//
// The default is [ModeAuto].
//
// Parameters:
//   - mode (Mode): the connection mode to use ([ModeAuto], [ModeCTLS],
//     [ModeZTLS], or [ModeOpenSSL]).
//
// Returns:
//   - of (Option): an OptionFunc that updates the Mode field of the options.
func WithMode(mode Mode) OptionFunc {
	return func(opts *Options) {
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
//   - of (Option): an OptionFunc that updates the Timeout field of the options.
func WithTimeout(timeout time.Duration) OptionFunc {
	return func(opts *Options) {
		opts.Timeout = timeout
	}
}

// WithServerName sets the Server Name Indication (SNI) name sent in the
// ClientHello.
//
// When unset, the inspected host is used. This is useful when inspecting by IP
// while presenting a hostname, or for virtual-host discovery.
//
// Parameters:
//   - serverName (string): the SNI name to send (e.g., "example.com").
//
// Returns:
//   - of (Option): an OptionFunc that updates the ServerName field of the options.
func WithServerName(serverName string) OptionFunc {
	return func(opts *Options) {
		opts.ServerName = serverName
	}
}

// WithCipherSuites sets the cipher suites offered in the ClientHello.
//
// When unset, the dialing library's default set is used. Restricting the
// list enables cipher-suite enumeration: inspect once per suite and read the
// negotiated [Result.CipherSuite].
//
// Parameters:
//   - cipherSuites ([]uint16): the cipher suite IDs to offer.
//
// Returns:
//   - of (Option): an OptionFunc that updates the CipherSuites field of the options.
func WithCipherSuites(cipherSuites []uint16) OptionFunc {
	return func(opts *Options) {
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
//   - of (Option): an OptionFunc that updates the MinVersion field of the options.
func WithMinVersion(minVersion uint16) OptionFunc {
	return func(opts *Options) {
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
//   - of (Option): an OptionFunc that updates the MaxVersion field of the options.
func WithMaxVersion(maxVersion uint16) OptionFunc {
	return func(opts *Options) {
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
//   - of (Option): an OptionFunc that updates the NextProtos field of the options.
func WithNextProtos(nextProtos ...string) OptionFunc {
	return func(opts *Options) {
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
//   - of (Option): an OptionFunc that updates the PreHandshake field of the options.
func WithPreHandshake(enabled bool) OptionFunc {
	return func(opts *Options) {
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
//   - of (Option): an OptionFunc that updates the Proxy field of the options.
func WithProxy(proxyAddress string) OptionFunc {
	return func(opts *Options) {
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
//   - of (Option): an OptionFunc that updates the OpenSSLBinary field of the options.
func WithOpenSSLBinary(path string) OptionFunc {
	return func(opts *Options) {
		opts.OpenSSLBinary = path
	}
}

// validateVersion reports whether version is a recognized TLS version or
// zero (library default).
//
// Parameters:
//   - version (uint16): the version ID to check.
//
// Returns:
//   - valid (bool): true when the version is recognized or zero; otherwise, false.
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
func (opts *Options) validate() (err error) {
	if opts.Timeout <= 0 {
		err = fmt.Errorf("invalid input, timeout must be positive, got %v", opts.Timeout)

		return err
	}

	if !validateVersion(opts.MinVersion) {
		err = fmt.Errorf("invalid input, unrecognized minimum TLS version: %#x", opts.MinVersion)

		return err
	}

	if !validateVersion(opts.MaxVersion) {
		err = fmt.Errorf("invalid input, unrecognized maximum TLS version: %#x", opts.MaxVersion)

		return err
	}

	if opts.MinVersion != 0 && opts.MaxVersion != 0 && opts.MinVersion > opts.MaxVersion {
		err = fmt.Errorf("invalid input, minimum TLS version %#x exceeds maximum %#x", opts.MinVersion, opts.MaxVersion)

		return err
	}

	return nil
}
