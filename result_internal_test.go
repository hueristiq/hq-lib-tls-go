package tls

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResultFields(t *testing.T) {
	t.Parallel()

	result := Result{
		Host:         "example.com",
		IP:           "192.0.2.1",
		Mode:         ModeCTLS,
		TLSVersion:   0x0303,
		CipherSuite:  0x1301,
		ALPN:         "h2",
		Certificates: [][]byte{{0x01}},
		ClientHello:  []byte{0x02},
		ServerHello:  []byte{0x03},
		Error:        errors.New("handshake failed"),
	}

	assert.Equal(t, "example.com", result.Host)
	assert.Equal(t, "192.0.2.1", result.IP)
	assert.Equal(t, ModeCTLS, result.Mode)
	assert.Equal(t, uint16(0x0303), result.TLSVersion)
	assert.Equal(t, uint16(0x1301), result.CipherSuite)
	assert.Equal(t, "h2", result.ALPN)
	assert.Equal(t, [][]byte{{0x01}}, result.Certificates)
	assert.Equal(t, []byte{0x02}, result.ClientHello)
	assert.Equal(t, []byte{0x03}, result.ServerHello)
	assert.EqualError(t, result.Error, "handshake failed")
}
