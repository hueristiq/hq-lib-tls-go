package tls

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectAutoFallsBackToCTLS(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)

	defer stop()

	client, err := New(WithMode(ModeAuto), WithTimeout(15*time.Second))

	require.NoError(t, err)

	result, err := client.Inspect(context.Background(), address)

	require.NoError(t, err)
	assert.NoError(t, result.Error)
	assert.Equal(t, ModeZTLS, result.Mode, "auto uses zcrypto when it succeeds")
	assert.NotEmpty(t, result.Certificates)
}

func TestInspectUnknownModeFallsBackToAuto(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)
	defer stop()

	client, err := New(WithMode(Mode(99)))
	require.NoError(t, err)

	result, err := client.Inspect(context.Background(), address)
	require.NoError(t, err)
	assert.Equal(t, ModeZTLS, result.Mode)
}

func TestInspectAutoFallbackHandshakeFailure(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, &fakeDialer{conn: &fakeConn{readErr: io.EOF}}, WithMode(ModeAuto))

	result, err := client.Inspect(context.Background(), "example.com:443")
	require.NoError(t, err)
	require.Error(t, result.Error)
	assert.Equal(t, ModeCTLS, result.Mode, "auto records the fallback mode")
}

func TestInspectAutoBothDialFailures(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, &fakeDialer{err: errors.New("dial failed")}, WithMode(ModeAuto))

	_, err := client.Inspect(context.Background(), "example.com:443")
	require.ErrorContains(t, err, "dial failed")
}
