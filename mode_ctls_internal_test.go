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
)

func TestInspectCTLS(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)

	defer stop()

	client, err := New(WithMode(ModeCTLS), WithTimeout(15*time.Second))

	require.NoError(t, err)

	result, err := client.Inspect(context.Background(), address)

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

func TestInspectCTLSSetDeadlineFailure(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, &fakeDialer{conn: &fakeConn{deadlineErr: errors.New("deadline failed")}}, WithMode(ModeCTLS))

	_, err := client.Inspect(context.Background(), "example.com:443")
	require.ErrorContains(t, err, "setting connection deadline")
}

func TestInspectCTLSHandshakeFailure(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, &fakeDialer{conn: &fakeConn{readErr: io.EOF}}, WithMode(ModeCTLS))

	result, err := client.Inspect(context.Background(), "example.com:443")
	require.NoError(t, err)
	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "handshake failed")
}
