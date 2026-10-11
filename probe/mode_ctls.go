package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// probeWithCTLS probes host through the Go standard library's crypto/tls.
//
// Parameters:
//   - ctx (context.Context): the context bounding the operation.
//   - host (string): the hostname or IP (without port).
//   - address (string): the dial address (host:port).
//
// Returns:
//   - result (Result): the probe outcome; [Result.Error] carries handshake failures.
//   - err (error): non-nil when the connection itself could not be established.
func (p *Prober) probeWithCTLS(ctx context.Context, host, address string) (result Result, err error) {
	result.Mode = ModeCTLS

	rawConn, err := p.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		err = fmt.Errorf("dialing %s: %w", address, err)

		return result, err
	}

	defer func() {
		_ = rawConn.Close()
	}()

	result.IP = remoteIP(rawConn)

	serverName := p.options.ServerName

	if serverName == "" {
		serverName = host
	}

	config := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the prober's purpose is to observe servers, including misconfigured ones.
		ServerName:         serverName,
		MinVersion:         p.options.MinVersion,
		MaxVersion:         p.options.MaxVersion,
		CipherSuites:       p.options.CipherSuites,
		NextProtos:         p.options.NextProtos,
	}

	tlsConn := tls.Client(rawConn, config)

	defer func() {
		_ = tlsConn.Close()
	}()

	if err = rawConn.SetDeadline(time.Now().Add(p.options.Timeout)); err != nil {
		err = fmt.Errorf("setting connection deadline: %w", err)

		return result, err
	}

	if err = tlsConn.HandshakeContext(ctx); err != nil {
		result.Error = fmt.Errorf("handshake failed: %w", err)

		return result, nil
	}

	state := tlsConn.ConnectionState()

	result.TLSVersion = state.Version
	result.CipherSuite = state.CipherSuite
	result.ALPN = state.NegotiatedProtocol

	for _, certificate := range state.PeerCertificates {
		result.Certificates = append(result.Certificates, certificate.Raw)
	}

	return result, nil
}

// remoteIP returns the IP part of the connection's remote address, or an
// empty string when it cannot be determined. Through a SOCKS5 proxy the
// remote address is the proxy's, so callers should not treat an empty
// result as a failure.
//
// Parameters:
//   - conn (net.Conn): the established connection.
//
// Returns:
//   - ip (string): the remote IP, if determinable.
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
