package probe

import (
	"context"
	"fmt"
	"time"

	zcryptotls "github.com/zmap/zcrypto/tls"
)

// probeWithZTLS probes host through zmap/zcrypto, capturing the raw
// ClientHello and ServerHello messages and tolerating servers the standard
// library rejects. With pre-handshake enabled, the recordingConn aborts the
// connection as soon as the ServerHello and certificates have been
// captured, before the client's key exchange; the resulting handshake
// error is then an expected outcome rather than a failure.
//
// Parameters:
//   - ctx (context.Context): the context bounding the operation.
//   - host (string): the hostname or IP (without port).
//   - address (string): the dial address (host:port).
//
// Returns:
//   - result (Result): the probe outcome; [Result.Error] carries handshake failures.
//   - err (error): non-nil when the connection itself could not be established.
func (p *Prober) probeWithZTLS(ctx context.Context, host, address string) (result Result, err error) {
	result.Mode = ModeZTLS

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

	config := &zcryptotls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         p.options.MinVersion,
		MaxVersion:         p.options.MaxVersion,
		CipherSuites:       p.options.CipherSuites,
		NextProtos:         p.options.NextProtos,
	}

	recording := newRecordingConn(rawConn, p.options.PreHandshake)

	tlsConn := zcryptotls.Client(recording, config)

	if err = rawConn.SetDeadline(time.Now().Add(p.options.Timeout)); err != nil {
		err = fmt.Errorf("setting connection deadline: %w", err)

		return result, err
	}

	handshakeErr := tlsConn.Handshake()

	handshake := tlsConn.GetHandshakeLog()

	if handshake != nil && handshake.ServerHello != nil {
		result.TLSVersion = uint16(handshake.ServerHello.Version)
		result.CipherSuite = uint16(handshake.ServerHello.CipherSuite)
		result.ALPN = handshake.ServerHello.AlpnProtocol
	}

	if handshake != nil && handshake.ServerCertificates != nil {
		chain := append([]zcryptotls.SimpleCertificate{handshake.ServerCertificates.Certificate}, handshake.ServerCertificates.Chain...)

		for _, certificate := range chain {
			if len(certificate.Raw) > 0 {
				result.Certificates = append(result.Certificates, certificate.Raw)
			}
		}
	}

	if raw := recording.clientHello(); raw != nil {
		result.ClientHello = raw
	}

	if raw := recording.serverHello(); raw != nil {
		result.ServerHello = raw
	}

	// In pre-handshake mode the early close turns the handshake error into
	// an expected outcome: the certificates that motivated the abort are
	// already captured, so the probe succeeded.
	if handshakeErr != nil && (!p.options.PreHandshake || len(result.Certificates) == 0) {
		result.Error = fmt.Errorf("handshake failed: %w", handshakeErr)
	}

	return result, nil
}
