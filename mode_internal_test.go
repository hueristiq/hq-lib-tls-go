package tls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMode(t *testing.T) {
	t.Parallel()

	tests := map[string]Mode{
		"":        ModeAuto,
		"auto":    ModeAuto,
		"ctls":    ModeCTLS,
		"ztls":    ModeZTLS,
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

	_, err := ParseMode("bogus")

	require.Error(t, err)
}

func TestModeString(t *testing.T) {
	t.Parallel()

	tests := map[Mode]string{
		ModeAuto:    "auto",
		ModeCTLS:    "ctls",
		ModeZTLS:    "ztls",
		ModeOpenSSL: "openssl",
		Mode(99):    "auto",
	}

	for mode, expected := range tests {
		t.Run(expected, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, expected, mode.String())
		})
	}
}
