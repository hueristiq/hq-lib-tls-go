package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectZTLS(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)

	defer stop()

	client, err := New(WithMode(ModeZTLS), WithTimeout(5*time.Second), WithNextProtos("h2", "http/1.1"))

	require.NoError(t, err)

	result, err := client.Inspect(context.Background(), address)

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

func TestInspectZTLSWithPreHandshake(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)

	defer stop()

	client, err := New(
		WithMode(ModeZTLS),
		WithTimeout(5*time.Second),
		WithPreHandshake(true),
	)

	require.NoError(t, err)

	result, err := client.Inspect(context.Background(), address)

	require.NoError(t, err)
	assert.NoError(t, result.Error, "pre-handshake abort is an expected outcome, not a failure")
	assert.NotEmpty(t, result.Certificates, "certificates are captured before the abort")
	assert.NotEmpty(t, result.ServerHello)
}

func TestInspectZTLSDialFailure(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, &fakeDialer{err: errors.New("dial failed")}, WithMode(ModeZTLS))

	_, err := client.Inspect(context.Background(), "example.com:443")
	require.ErrorContains(t, err, "dial failed")
}

func TestInspectZTLSSetDeadlineFailure(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, &fakeDialer{conn: &fakeConn{deadlineErr: errors.New("deadline failed")}}, WithMode(ModeZTLS))

	_, err := client.Inspect(context.Background(), "example.com:443")
	require.ErrorContains(t, err, "setting connection deadline")
}

func TestInspectZTLSHandshakeFailureWithPreHandshake(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, &fakeDialer{conn: &fakeConn{readErr: io.EOF}}, WithMode(ModeZTLS), WithPreHandshake(true))

	result, err := client.Inspect(context.Background(), "example.com:443")
	require.NoError(t, err)
	require.Error(t, result.Error, "a handshake failure without captured certificates is still reported")
}
