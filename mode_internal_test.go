package tls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMode(t *testing.T) {
	t.Parallel()

	tests := map[string]Mode{
		"":        ModeCTLS,
		"ctls":    ModeCTLS,
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

	for _, name := range []string{"auto", "ztls", "bogus"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseMode(name)

			require.Error(t, err)
		})
	}
}

func TestModeString(t *testing.T) {
	t.Parallel()

	tests := map[Mode]string{
		ModeCTLS:    "ctls",
		ModeOpenSSL: "openssl",
		Mode(99):    "ctls",
	}

	for mode, expected := range tests {
		t.Run(expected, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, expected, mode.String())
		})
	}
}
