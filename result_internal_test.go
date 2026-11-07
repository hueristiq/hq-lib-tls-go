package tls

import (
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
	}

	assert.Equal(t, "example.com", result.Host)
	assert.Equal(t, "192.0.2.1", result.IP)
	assert.Equal(t, ModeCTLS, result.Mode)
	assert.Equal(t, uint16(0x0303), result.TLSVersion)
	assert.Equal(t, uint16(0x1301), result.CipherSuite)
	assert.Equal(t, "h2", result.ALPN)
	assert.Equal(t, [][]byte{{0x01}}, result.Certificates)
}
