package tlsprobe

import (
	"strings"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// Mode selects how a [Client] establishes its TLS connection.
type Mode int

const (
	// ModeCTLS dials through the Go standard library's crypto/tls. It is the
	// zero value and the default.
	ModeCTLS Mode = iota
	// ModeOpenSSL shells out to the OpenSSL binary (s_client) and parses
	// its session output.
	ModeOpenSSL
)

// String returns the CLI-facing name of the mode: "ctls" or "openssl".
// Modes outside the enumerated set render as "unknown".
func (m Mode) String() (name string) {
	switch m {
	case ModeCTLS:
		name = "ctls"
	case ModeOpenSSL:
		name = "openssl"
	default:
		name = "unknown"
	}

	return name
}

// ParseMode converts a mode name into a [Mode]. It accepts "ctls" and
// "openssl", plus the empty string for [ModeCTLS].
func ParseMode(name string) (mode Mode, err error) {
	switch strings.ToLower(name) {
	case "", "ctls":
		mode = ModeCTLS
	case "openssl":
		mode = ModeOpenSSL
	default:
		err = hqgoerrors.Errorf("invalid input, unrecognized TLS connection mode: %q", name)

		return mode, err
	}

	return mode, nil
}
