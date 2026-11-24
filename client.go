package tls

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	"golang.org/x/net/proxy"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	hqgotlscertificate "github.com/hueristiq/hq-lib-tls-go/certificate"
	hqgotlsclient "github.com/hueristiq/hq-lib-tls-go/client"
)

const (
	// defaultPort is appended to hosts given without a port.
	defaultPort = "443"
	// defaultTimeout is the per-connection timeout used when [WithTimeout]
	// is not given.
	defaultTimeout = 5 * time.Second
)

// A Client connects to TLS servers and captures what they offer. It is
// immutable after construction and safe for concurrent use: [Inspect],
// [EnumerateVersions], [EnumerateCipherSuites], and [JARM] open independent
// connections per call.
type Client struct {
	options Options
	dialer  proxy.ContextDialer
}

// Options configures a [Client].
//
// Fields:
//   - Config (*client.Config): the connection configuration. Nil uses a default
//     config that skips certificate verification, matching the probing use
//     case.
//   - Timeout (time.Duration): the per-connection timeout.
//   - Proxy (string): a SOCKS5 proxy address; empty disables proxying.
type Options struct {
	Config  *hqgotlsclient.Config
	Timeout time.Duration
	Proxy   string
}

// OptionFunc configures a [Client] created by [New]. A nil OptionFunc is
// ignored. Options are applied in order, so later options override earlier
// ones.
type OptionFunc func(opts *Options)

// New creates a Client. Unset options fall back to their defaults, and
// invalid values are rejected.
func New(ofs ...OptionFunc) (client *Client, err error) {
	opts := &Options{
		Config:  &hqgotlsclient.Config{InsecureSkipVerify: true},
		Timeout: defaultTimeout,
	}

	for _, f := range ofs {
		if f == nil {
			continue
		}

		f(opts)
	}

	if opts.Config == nil {
		opts.Config = &hqgotlsclient.Config{InsecureSkipVerify: true}
	}

	opts.Config = opts.Config.Clone()

	if err = opts.Config.Validate(); err != nil {
		return nil, hqgoerrors.Stack(err)
	}

	if opts.Timeout <= 0 {
		return nil, hqgoerrors.Errorf("invalid input, timeout must be positive, got %v", opts.Timeout)
	}

	client = &Client{
		options: *opts,
		dialer:  proxy.Direct,
	}

	if opts.Proxy != "" {
		socks5, _ := proxy.SOCKS5("tcp", opts.Proxy, nil, proxy.Direct)
		client.dialer = socks5.(proxy.ContextDialer)
	}

	return client, nil
}

// Inspect connects to host and captures the negotiated parameters,
// certificates, and handshake trace.
//
// The host may be given with or without a port; without one, 443 is used.
// Dialing and handshake failures are returned as err. A reached server yields
// a partial result containing its address, any captured state, and the
// handshake trace; callers must check err before relying on negotiated
// parameters.
func (p *Client) Inspect(ctx context.Context, host string) (result Result, err error) {
	host, port, err := splitHostPort(host)
	if err != nil {
		return Result{}, hqgoerrors.Stack(err)
	}

	address := net.JoinHostPort(host, port)

	config := p.options.Config.Clone()

	if config.ServerName == "" && net.ParseIP(host) == nil {
		config.ServerName = host
	}

	conn, dialErr := hqgotlsclient.DialWithDialerContext(ctx, p.dialer, "tcp", address, config)
	if conn != nil {
		state := conn.ConnectionState()

		result.Host = host
		result.IP = remoteIP(conn.NetConn())
		result.TLSVersion = state.Version
		result.CipherSuite = state.CipherSuite
		result.ALPN = state.NegotiatedProtocol
		result.ExportCipher = state.ExportCipher
		result.Handshake = conn.HandshakeLog()
		result.Trace = conn.HandshakeTrace()

		for _, certificate := range state.PeerCertificates {
			result.Certificates = append(result.Certificates, certificate.Raw)
		}

		if len(result.Certificates) > 0 {
			if report, reportErr := hqgotlscertificate.Analyze(result.Certificates, host, time.Now()); reportErr == nil {
				result.CertificateReport = report
			}
		}

		_ = conn.Close()
	}

	if dialErr != nil {
		if conn != nil {
			dialErr = hqgoerrors.Join(ErrHandshake, dialErr)
		}

		return result, hqgoerrors.Wrapf(dialErr, "inspecting %s", host)
	}

	result.Host = host

	return result, nil
}

// splitHostPort splits host into its hostname and port parts, defaulting the
// port to 443 when absent. IPv6 literals must be bracketed.
func splitHostPort(host string) (hostname, port string, err error) {
	if host == "" {
		return "", "", hqgoerrors.New("invalid input, host is empty")
	}

	hostname, port, err = net.SplitHostPort(host)
	if err != nil {
		hostname, port = host, defaultPort
	}

	return hostname, port, nil
}

// remoteIP returns the IP part of the connection's remote address, or an
// empty string when it cannot be determined.
func remoteIP(conn net.Conn) (ip string) {
	if conn == nil {
		return ""
	}

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err == nil {
		ip = host
	}

	return ip
}

// WithConfig sets the connection configuration. The config is cloned.
func WithConfig(config *hqgotlsclient.Config) (fn OptionFunc) {
	return func(opts *Options) {
		if config == nil {
			return
		}

		opts.Config = config.Clone()
	}
}

// WithTimeout sets the per-connection timeout.
func WithTimeout(timeout time.Duration) (fn OptionFunc) {
	return func(opts *Options) {
		opts.Timeout = timeout
	}
}

// WithServerName sets the Server Name Indication (SNI) name.
func WithServerName(serverName string) (fn OptionFunc) {
	return func(opts *Options) {
		ensureConfig(opts).ServerName = serverName
	}
}

// WithCipherSuites sets the cipher suites offered in the ClientHello.
func WithCipherSuites(cipherSuites []uint16) (fn OptionFunc) {
	return func(opts *Options) {
		ensureConfig(opts).CipherSuites = append([]uint16(nil), cipherSuites...)
	}
}

// WithMinVersion sets the minimum TLS version offered.
func WithMinVersion(minVersion uint16) (fn OptionFunc) {
	return func(opts *Options) {
		ensureConfig(opts).MinVersion = minVersion
	}
}

// WithMaxVersion sets the maximum TLS version offered.
func WithMaxVersion(maxVersion uint16) (fn OptionFunc) {
	return func(opts *Options) {
		ensureConfig(opts).MaxVersion = maxVersion
	}
}

// WithNextProtos sets the ALPN protocols advertised.
func WithNextProtos(nextProtos ...string) (fn OptionFunc) {
	return func(opts *Options) {
		ensureConfig(opts).NextProtos = append([]string(nil), nextProtos...)
	}
}

// WithProxy sets a SOCKS5 proxy for the connection.
func WithProxy(proxyAddress string) (fn OptionFunc) {
	return func(opts *Options) {
		opts.Proxy = proxyAddress
	}
}

// WithHandshakeLogger sets the streaming handshake message callback.
func WithHandshakeLogger(logger func(hqgotlsclient.HandshakeEvent)) (fn OptionFunc) {
	return func(opts *Options) {
		ensureConfig(opts).HandshakeLogger = logger
	}
}

// WithClientHelloSpec sets an explicit ClientHello specification.
func WithClientHelloSpec(spec *hqgotlsclient.HelloSpec) (fn OptionFunc) {
	return func(opts *Options) {
		ensureConfig(opts).ClientHelloSpec = spec
	}
}

// WithRootCAs sets the certificate trust store used when verification is
// enabled.
func WithRootCAs(roots *x509.CertPool) (fn OptionFunc) {
	return func(opts *Options) {
		ensureConfig(opts).RootCAs = roots
	}
}

// WithInsecureSkipVerify controls certificate verification. The default for
// a probing client is true.
func WithInsecureSkipVerify(skip bool) (fn OptionFunc) {
	return func(opts *Options) {
		ensureConfig(opts).InsecureSkipVerify = skip
	}
}

// WithAllowExportCipherSuites permits export-grade cipher suites.
func WithAllowExportCipherSuites(allow bool) (fn OptionFunc) {
	return func(opts *Options) {
		ensureConfig(opts).AllowExportCipherSuites = allow
	}
}

// ensureConfig returns the options' config, creating one if needed.
func ensureConfig(opts *Options) (config *hqgotlsclient.Config) {
	if opts.Config == nil {
		opts.Config = &hqgotlsclient.Config{InsecureSkipVerify: true}
	}

	return opts.Config
}

// cloneWith returns a client sharing the dialer but with a copied config
// updated by update.
func (p *Client) cloneWith(update func(*hqgotlsclient.Config)) (client *Client) {
	opts := p.options
	opts.Config = p.options.Config.Clone()

	update(opts.Config)

	client = &Client{
		options: opts,
		dialer:  p.dialer,
	}

	return client
}
