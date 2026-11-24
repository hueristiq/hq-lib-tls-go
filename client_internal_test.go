package tls

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hqgotlsclient "github.com/hueristiq/hq-lib-tls-go/client"
)

func TestNewRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	tests := map[string][]OptionFunc{
		"zero timeout":     {WithTimeout(0)},
		"negative timeout": {WithTimeout(-time.Second)},
		"unknown min":      {WithMinVersion(0x0b0b)},
		"unknown max":      {WithMaxVersion(0x0b0b)},
		"min exceeds max":  {WithMinVersion(hqgotlsclient.VersionTLS13), WithMaxVersion(hqgotlsclient.VersionTLS12)},
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

func TestOptionsMutateConfig(t *testing.T) {
	t.Parallel()

	client, err := New(
		WithTimeout(3*time.Second),
		WithServerName("example.com"),
		WithCipherSuites([]uint16{0xC02F}),
		WithMinVersion(hqgotlsclient.VersionTLS12),
		WithMaxVersion(hqgotlsclient.VersionTLS13),
		WithNextProtos("h2", "http/1.1"),
		WithAllowExportCipherSuites(true),
		WithHandshakeLogger(func(hqgotlsclient.HandshakeEvent) {}),
	)

	require.NoError(t, err)
	require.NotNil(t, client)

	assert.Equal(t, 3*time.Second, client.options.Timeout)
	assert.Equal(t, "example.com", client.options.Config.ServerName)
	assert.Equal(t, []uint16{0xC02F}, client.options.Config.CipherSuites)
	assert.Equal(t, hqgotlsclient.VersionTLS12, client.options.Config.MinVersion)
	assert.Equal(t, hqgotlsclient.VersionTLS13, client.options.Config.MaxVersion)
	assert.Equal(t, []string{"h2", "http/1.1"}, client.options.Config.NextProtos)
	assert.True(t, client.options.Config.AllowExportCipherSuites)
	assert.NotNil(t, client.options.Config.HandshakeLogger)
}
