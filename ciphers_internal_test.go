package tls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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

// TestCiphersTableSmoke anchors the generated table that used to live in
// ciphers_table.go; TestCipherClassification exercises its contents.
func TestCiphersTableSmoke(t *testing.T) {
	t.Parallel()
}
