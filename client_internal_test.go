package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
)

func TestNewRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	tests := map[string][]OptionFunc{
		"zero timeout":     {WithTimeout(0)},
		"negative timeout": {WithTimeout(-time.Second)},
		"unknown min":      {WithMinVersion(0x0b0b)},
		"unknown max":      {WithMaxVersion(0x0b0b)},
		"min exceeds max":  {WithMinVersion(tls.VersionTLS13), WithMaxVersion(tls.VersionTLS12)},
	}

	for name, options := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client, err := New(options...)

			require.Error(t, err)
			assert.Nil(t, client)
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

func TestInspectFailsToDial(t *testing.T) {
	t.Parallel()

	client, err := New(WithMode(ModeCTLS), WithTimeout(time.Second))

	require.NoError(t, err)

	// Port 1 on localhost is conventionally closed.
	result, err := client.Inspect(context.Background(), "127.0.0.1:1")

	require.Error(t, err)
	assert.Empty(t, result.Host)
}

type fakeAddr string

type fakeConn struct {
	readData    []byte
	readErr     error
	writeErr    error
	deadlineErr error
}

type fakeDialer struct {
	conn net.Conn
	err  error
}

type timeoutError struct{}

type failingReader struct{}

func newTestClient(t *testing.T, dialer proxy.ContextDialer, ofs ...OptionFunc) (client *Client) {
	t.Helper()

	client, err := New(ofs...)
	require.NoError(t, err)

	client.dialer = dialer

	return client
}

func TestOptionSetters(t *testing.T) {
	t.Parallel()

	opts := &Options{}

	WithMode(ModeCTLS)(opts)
	WithTimeout(time.Second)(opts)
	WithServerName("example.com")(opts)
	WithCipherSuites([]uint16{0x1301})(opts)
	WithMinVersion(tls.VersionTLS12)(opts)
	WithMaxVersion(tls.VersionTLS13)(opts)
	WithNextProtos("h2", "http/1.1")(opts)
	WithProxy("127.0.0.1:9050")(opts)
	WithOpenSSLBinary("/usr/bin/openssl")(opts)

	assert.Equal(t, ModeCTLS, opts.Mode)
	assert.Equal(t, time.Second, opts.Timeout)
	assert.Equal(t, "example.com", opts.ServerName)
	assert.Equal(t, []uint16{0x1301}, opts.CipherSuites)
	assert.Equal(t, uint16(tls.VersionTLS12), opts.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), opts.MaxVersion)
	assert.Equal(t, []string{"h2", "http/1.1"}, opts.NextProtos)
	assert.Equal(t, "127.0.0.1:9050", opts.Proxy)
	assert.Equal(t, "/usr/bin/openssl", opts.OpenSSLBinary)
}

func TestNewWithProxy(t *testing.T) {
	t.Parallel()

	client, err := New(WithProxy("127.0.0.1:9050"))
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotEqual(t, proxy.Direct, client.dialer)
}

func TestInspectInvalidHost(t *testing.T) {
	t.Parallel()

	client, err := New()
	require.NoError(t, err)

	_, err = client.Inspect(context.Background(), "")
	require.ErrorContains(t, err, "host is empty")
}

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
		hqgotlsauthority.WithCACommonName("client test CA"),
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

func (a fakeAddr) Network() (network string) { return "tcp" }

func (a fakeAddr) String() (address string) { return string(a) }

func (c *fakeConn) Read(b []byte) (n int, err error) {
	if c.readErr != nil {
		return 0, c.readErr
	}

	if len(c.readData) == 0 {
		return 0, io.EOF
	}

	n = copy(b, c.readData)
	c.readData = c.readData[n:]

	return n, nil
}

func (c *fakeConn) Write(b []byte) (n int, err error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}

	return len(b), nil
}

func (c *fakeConn) Close() (err error) { return nil }

func (c *fakeConn) LocalAddr() (address net.Addr) { return fakeAddr("127.0.0.1:1") }

func (c *fakeConn) RemoteAddr() (address net.Addr) { return fakeAddr("127.0.0.1:443") }

func (c *fakeConn) SetDeadline(time.Time) (err error) { return c.deadlineErr }

func (c *fakeConn) SetReadDeadline(time.Time) (err error) { return c.deadlineErr }

func (c *fakeConn) SetWriteDeadline(time.Time) (err error) { return c.deadlineErr }

func (d *fakeDialer) DialContext(context.Context, string, string) (conn net.Conn, err error) {
	if d.err != nil {
		return nil, d.err
	}

	return d.conn, nil
}

func (timeoutError) Error() (message string) { return "i/o timeout" }

func (timeoutError) Timeout() (timedOut bool) { return true }

func (timeoutError) Temporary() (temporary bool) { return true }

func (failingReader) Read([]byte) (n int, err error) { return 0, errors.New("entropy source failed") }
