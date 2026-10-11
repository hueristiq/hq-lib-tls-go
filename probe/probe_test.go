package probe

import (
	"context"
	"crypto/tls"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
)

// startTLSServer starts a local TLS 1.2 server on 127.0.0.1 and returns
// its address. The server presents a certificate minted for "localhost" by
// an ephemeral CA generated per test.
//
// Parameters:
//   - tb (testing.TB): the test handle.
//
// Returns:
//   - address (string): the server's host:port address.
//   - stop (func()): stops the server and closes the listener.
func startTLSServer(tb testing.TB) (address string, stop func()) {
	tb.Helper()

	caCertificate, caPrivateKey, err := hqgotlsauthority.GenerateCACertificatePrivateKey(
		hqgotlsauthority.WithCACommonName("probe test CA"),
		hqgotlsauthority.WithCAKeyType(hqgotlsauthority.KeyTypeECDSAP256),
	)

	require.NoError(tb, err)

	authority, err := hqgotlsauthority.New(caCertificate, caPrivateKey)

	require.NoError(tb, err)

	certificate, err := authority.TLSCertificate("localhost")

	require.NoError(tb, err)

	// TLS 1.2 only: the pre-handshake capture is effective up to 1.2, so
	// the tests pin the version instead of negotiating 1.3.
	config := &tls.Config{ //nolint:gosec // G402: the tests deliberately pin TLS 1.2.
		Certificates: []tls.Certificate{*certificate},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)

	require.NoError(tb, err)

	done := make(chan struct{})

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				close(done)

				return
			}

			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.HandshakeContext(context.Background())
			}

			_ = conn.Close()
		}
	}()

	address = listener.Addr().String()

	stop = func() {
		_ = listener.Close()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			tb.Fatal("test TLS server did not stop")
		}
	}

	return address, stop
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	tests := map[string][]Option{
		"zero timeout":     {WithTimeout(0)},
		"negative timeout": {WithTimeout(-time.Second)},
		"unknown min":      {WithMinVersion(0x0b0b)},
		"unknown max":      {WithMaxVersion(0x0b0b)},
		"min exceeds max":  {WithMinVersion(tls.VersionTLS13), WithMaxVersion(tls.VersionTLS12)},
	}

	for name, options := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			prober, err := New(options...)

			require.Error(t, err)
			assert.Nil(t, prober)
		})
	}
}

func TestSplitHostPort(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		host     string
		hostname string
		port     string
		wantErr  bool
	}{
		"plain hostname": {host: "example.com", hostname: "example.com", port: "443"},
		"host with port": {host: "example.com:8443", hostname: "example.com", port: "8443"},
		"ip":             {host: "1.2.3.4", hostname: "1.2.3.4", port: "443"},
		"ip with port":   {host: "1.2.3.4:444", hostname: "1.2.3.4", port: "444"},
		"bracketed ipv6": {host: "[::1]:443", hostname: "::1", port: "443"},
		"empty":          {host: "", wantErr: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hostname, port, err := splitHostPort(test.host)

			if test.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.hostname, hostname)
			assert.Equal(t, test.port, port)
		})
	}
}

func TestProbeCTLS(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)

	defer stop()

	prober, err := New(WithMode(ModeCTLS), WithTimeout(5*time.Second))

	require.NoError(t, err)

	result, err := prober.Probe(context.Background(), address)

	require.NoError(t, err)
	assert.NoError(t, result.Error)
	assert.Equal(t, ModeCTLS, result.Mode)
	assert.Equal(t, uint16(tls.VersionTLS12), result.TLSVersion)
	assert.NotZero(t, result.CipherSuite)
	assert.NotEmpty(t, result.Certificates)
	assert.Empty(t, result.ClientHello, "ctls mode has no handshake capture")
	assert.Empty(t, result.ServerHello, "ctls mode has no handshake capture")
	assert.Equal(t, "127.0.0.1", result.IP)
}

func TestProbeZTLS(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)

	defer stop()

	prober, err := New(WithMode(ModeZTLS), WithTimeout(5*time.Second), WithNextProtos("h2", "http/1.1"))

	require.NoError(t, err)

	result, err := prober.Probe(context.Background(), address)

	require.NoError(t, err)
	assert.NoError(t, result.Error)
	assert.Equal(t, ModeZTLS, result.Mode)
	assert.Equal(t, uint16(tls.VersionTLS12), result.TLSVersion)
	assert.NotZero(t, result.CipherSuite)
	assert.NotEmpty(t, result.Certificates)
	assert.NotEmpty(t, result.ClientHello, "ztls mode captures the ClientHello")
	assert.NotEmpty(t, result.ServerHello, "ztls mode captures the ServerHello")
	assert.Equal(t, "h2", result.ALPN, "the server selects its first preference")
}

func TestProbeZTLSWithPreHandshake(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)

	defer stop()

	prober, err := New(
		WithMode(ModeZTLS),
		WithTimeout(5*time.Second),
		WithPreHandshake(true),
	)

	require.NoError(t, err)

	result, err := prober.Probe(context.Background(), address)

	require.NoError(t, err)
	assert.NoError(t, result.Error, "pre-handshake abort is an expected outcome, not a failure")
	assert.NotEmpty(t, result.Certificates, "certificates are captured before the abort")
	assert.NotEmpty(t, result.ServerHello)
}

func TestProbeAutoFallsBackToCTLS(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)

	defer stop()

	prober, err := New(WithMode(ModeAuto), WithTimeout(5*time.Second))

	require.NoError(t, err)

	result, err := prober.Probe(context.Background(), address)

	require.NoError(t, err)
	assert.NoError(t, result.Error)
	assert.Equal(t, ModeZTLS, result.Mode, "auto uses zcrypto when it succeeds")
	assert.NotEmpty(t, result.Certificates)
}

func TestProbeOpenSSL(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl binary is not available")
	}

	address, stop := startTLSServer(t)

	defer stop()

	prober, err := New(WithMode(ModeOpenSSL), WithTimeout(10*time.Second))

	require.NoError(t, err)

	result, err := prober.Probe(context.Background(), address)

	require.NoError(t, err)
	assert.Equal(t, ModeOpenSSL, result.Mode)
	assert.NotZero(t, result.TLSVersion)
	assert.NotZero(t, result.CipherSuite)
	assert.NotEmpty(t, result.Certificates, "openssl mode extracts the certificate chain")
}

func TestProbeFailsToDial(t *testing.T) {
	t.Parallel()

	prober, err := New(WithMode(ModeCTLS), WithTimeout(time.Second))

	require.NoError(t, err)

	// Port 1 on localhost is conventionally closed.
	result, err := prober.Probe(context.Background(), "127.0.0.1:1")

	require.Error(t, err)
	assert.Empty(t, result.Host)
}

func TestJARM(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)

	defer stop()

	prober, err := New(WithTimeout(5 * time.Second))

	require.NoError(t, err)

	jarm, err := prober.JARM(context.Background(), address)

	require.NoError(t, err)
	assert.Len(t, jarm, 62)
	assert.NotEqual(t, jarmEmptyHash, jarm, "a responsive server yields a real fingerprint")
}

func TestJARMUnreachableHost(t *testing.T) {
	t.Parallel()

	prober, err := New(WithTimeout(time.Second))

	require.NoError(t, err)

	jarm, err := prober.JARM(context.Background(), "127.0.0.1:1")

	require.NoError(t, err)
	assert.Equal(t, jarmEmptyHash, jarm)
}

func TestParseMode(t *testing.T) {
	t.Parallel()

	tests := map[string]Mode{
		"":        ModeAuto,
		"auto":    ModeAuto,
		"ctls":    ModeCTLS,
		"ztls":    ModeZTLS,
		"openssl": ModeOpenSSL,
		"OPENSSL": ModeOpenSSL,
	}

	for name, expected := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mode, err := ParseMode(name)

			require.NoError(t, err)
			assert.Equal(t, expected, mode)
		})
	}

	_, err := ParseMode("bogus")

	require.Error(t, err)
}

func TestCipherClassification(t *testing.T) {
	t.Parallel()

	security, known := CipherSecurityOf(0x1301) // TLS_AES_128_GCM_SHA256

	assert.True(t, known)
	assert.Equal(t, CipherSecurityRecommended, security)

	_, known = CipherSecurityOf(0xdead)

	assert.False(t, known)

	secure := CipherSuitesBySecurity(CipherSecuritySecure)

	assert.NotEmpty(t, secure)
	assert.Contains(t, secure, uint16(0x1301))
}

func TestRemoteIP(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)

	defer stop()

	dialer := &net.Dialer{}

	conn, err := dialer.DialContext(context.Background(), "tcp", address)

	require.NoError(t, err)

	defer func() {
		_ = conn.Close()
	}()

	assert.Equal(t, "127.0.0.1", remoteIP(conn))
	assert.Empty(t, remoteIP(nil))
}
