package tls

import (
	"fmt"
	"strings"
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
// Modes outside the enumerated set render as "ctls", the zero value's name.
//
// Returns:
//   - name (string): the mode's name.
func (m Mode) String() (name string) {
	switch m {
	case ModeCTLS:
		name = "ctls"
	case ModeOpenSSL:
		name = "openssl"
	default:
		name = "ctls"
	}

	return name
}

// ParseMode converts a mode name into a [Mode]. It accepts "ctls" and
// "openssl", plus the empty string for [ModeCTLS].
//
// Parameters:
//   - name (string): the mode name to parse.
//
// Returns:
//   - mode (Mode): the parsed mode; [ModeCTLS] when name is empty.
//   - err (error): non-nil when name is not a recognized mode.
func ParseMode(name string) (mode Mode, err error) {
	switch strings.ToLower(name) {
	case "", "ctls":
		mode = ModeCTLS
	case "openssl":
		mode = ModeOpenSSL
	default:
		err = fmt.Errorf("client.ParseMode: invalid input, unrecognized TLS connection mode: %q", name)

		return mode, err
	}

	return mode, nil
}
