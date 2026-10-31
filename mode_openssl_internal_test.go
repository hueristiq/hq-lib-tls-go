package tls

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectOpenSSL(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl binary is not available")
	}

	address, stop := startTLSServer(t)

	defer stop()

	client, err := New(WithMode(ModeOpenSSL), WithTimeout(10*time.Second))

	require.NoError(t, err)

	result, err := client.Inspect(context.Background(), address)

	require.NoError(t, err)
	assert.Equal(t, ModeOpenSSL, result.Mode)
	assert.NotZero(t, result.TLSVersion)
	assert.NotZero(t, result.CipherSuite)
	assert.NotEmpty(t, result.Certificates, "openssl mode extracts the certificate chain")
}

func TestInspectOpenSSLMissingBinary(t *testing.T) {
	t.Parallel()

	client, err := New(WithMode(ModeOpenSSL), WithOpenSSLBinary("/nonexistent/openssl-binary"))
	require.NoError(t, err)

	_, err = client.Inspect(context.Background(), "example.com:443")
	require.ErrorContains(t, err, "inspectWithOpenSSL")
}

func TestParseOpenSSLOutputBranches(t *testing.T) {
	t.Parallel()

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01, 0x02, 0x03}})

	output := strings.Join([]string{
		"Protocol  : TLSv1.2",
		"Protocol",
		"New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384",
		"Cipher    : ECDHE-RSA-AES128-GCM-SHA256",
		"ALPN protocol: h2",
		"ALPN protocol:",
		string(certificatePEM),
	}, "\n")

	var result Result

	require.NoError(t, parseOpenSSLOutput(output, "example.com:443", &result))
	assert.Equal(t, uint16(tls.VersionTLS12), result.TLSVersion)
	assert.NotZero(t, result.CipherSuite)
	assert.Equal(t, "h2", result.ALPN)
	require.Len(t, result.Certificates, 1)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, result.Certificates[0])

	err := parseOpenSSLOutput("no session here", "example.com:443", &result)
	require.ErrorContains(t, err, "no session in OpenSSL output")
}

func TestRemoteIPFromOpenSSL(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"no connecting line":      "",
		"short connecting line":   "",
		"connecting line with IP": "127.0.0.1",
	}

	outputs := map[string]string{
		"no connecting line":      "CONNECTED(00000003)\n",
		"short connecting line":   "Connecting to \n",
		"connecting line with IP": "Connecting to 127.0.0.1:443\n",
	}

	for name, expected := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, expected, remoteIPFromOpenSSL(outputs[name]))
		})
	}
}
