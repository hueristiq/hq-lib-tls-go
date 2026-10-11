package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"golang.org/x/net/proxy"
)

const (
	// defaultPort is appended to hosts given without a port.
	defaultPort = "443"
)

// A Prober connects to TLS servers and captures what they offer. It is
// immutable after construction and safe for concurrent use: [Probe] and
// [JARM] open independent connections per call.
//
// Fields:
//   - options (options): the resolved connection configuration.
//   - dialer (proxy.ContextDialer): the dialer used for every connection,
//     wrapping the SOCKS5 proxy when one is configured.
type Prober struct {
	options options
	dialer  proxy.ContextDialer
}

// New creates a Prober. Unset options fall back to their defaults, and
// invalid values are rejected.
//
// Parameters:
//   - ofs (...Option): a variadic list of Option functions to configure
//     the prober (e.g., [WithMode], [WithTimeout]).
//
// Returns:
//   - prober (*Prober): the initialized prober.
//   - err (error): an error if an option value is invalid; otherwise, nil.
func New(ofs ...Option) (prober *Prober, err error) {
	opts := &options{
		Mode:          defaultMode,
		Timeout:       defaultTimeout,
		OpenSSLBinary: defaultOpenSSLBinary,
	}

	for _, f := range ofs {
		f(opts)
	}

	if err = opts.validate(); err != nil {
		err = fmt.Errorf("probe.New: %w", err)

		return nil, err
	}

	prober = &Prober{
		options: *opts,
		dialer:  proxy.Direct,
	}

	if opts.Proxy != "" {
		var socks5 proxy.Dialer

		socks5, err = proxy.SOCKS5("tcp", opts.Proxy, nil, proxy.Direct)
		if err != nil {
			err = fmt.Errorf("probe.New: creating SOCKS5 dialer for proxy %q: %w", opts.Proxy, err)

			return nil, err
		}

		prober.dialer = socks5.(proxy.ContextDialer)
	}

	return prober, nil
}

// Probe connects to host and captures the negotiated parameters,
// certificates, and handshake messages according to the configured mode.
//
// The host may be given with or without a port; without one, 443 is used.
// Dialing failures (unreachable host, connection refused, exhausted
// context) are returned as err; a reached server whose handshake fails
// yields a result carrying [Result.Error] instead, so callers can still
// report probe status.
//
// Parameters:
//   - ctx (context.Context): the context bounding the whole operation.
//   - host (string): the target, as hostname, IP, "host:port", or "IP:port".
//
// Returns:
//   - result (Result): the probe outcome; valid even when the handshake failed.
//   - err (error): non-nil only when no connection could be established.
func (p *Prober) Probe(ctx context.Context, host string) (result Result, err error) {
	host, port, err := splitHostPort(host)
	if err != nil {
		err = fmt.Errorf("probe.Probe: %w", err)

		return Result{}, err
	}

	address := net.JoinHostPort(host, port)

	switch p.options.Mode {
	case ModeAuto:
		result, err = p.probeWithAuto(ctx, host, address)
	case ModeCTLS:
		result, err = p.probeWithCTLS(ctx, host, address)
	case ModeZTLS:
		result, err = p.probeWithZTLS(ctx, host, address)
	case ModeOpenSSL:
		result, err = p.probeWithOpenSSL(ctx, host, address)
	default:
		// Out-of-range modes behave as auto, like the zero value.
		result, err = p.probeWithAuto(ctx, host, address)
	}

	if err != nil {
		err = fmt.Errorf("probe.Probe: probing %s: %w", host, err)

		return Result{}, err
	}

	result.Host = host

	return result, nil
}

// splitHostPort splits host into its hostname and port parts, defaulting
// the port to 443 when absent. IPv6 literals must be bracketed, as in
// net.JoinHostPort's syntax.
//
// Parameters:
//   - host (string): the target as given by the caller.
//
// Returns:
//   - hostname (string): the host without port.
//   - port (string): the port as a decimal string.
//   - err (error): non-nil when the input is empty or the port is invalid.
func splitHostPort(host string) (hostname, port string, err error) {
	if host == "" {
		err = errors.New("probe.splitHostPort: invalid input, host is empty")

		return "", "", err
	}

	hostname, port, err = net.SplitHostPort(host)
	if err == nil {
		return hostname, port, nil
	}

	if hostname == "" && port == "" {
		// SplitHostPort failed for a reason other than a missing port
		// (for example a bare IPv6 literal); treat the input as the
		// hostname with the default port.
		hostname, port = host, defaultPort
	}

	if _, err = strconv.ParseUint(port, 10, 16); err != nil {
		err = fmt.Errorf("probe.splitHostPort: invalid input, invalid port in host %q: %w", host, err)

		return "", "", err
	}

	return hostname, port, nil
}
