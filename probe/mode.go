package probe

import (
	"fmt"
	"strings"
)

// Mode selects how a [Prober] establishes its TLS connection.
type Mode int

const (
	// ModeAuto attempts the connection with zcrypto ([ModeZTLS]) and falls
	// back to the standard library ([ModeCTLS]) when zcrypto fails. It is
	// the default and maximizes coverage across old and unusual servers.
	ModeAuto Mode = iota
	// ModeCTLS dials through the Go standard library's crypto/tls. It has
	// no raw handshake capture, so fingerprints are unavailable.
	ModeCTLS
	// ModeZTLS dials through zmap/zcrypto, capturing the raw ClientHello
	// and ServerHello messages. It tolerates older TLS versions and
	// malformed servers that crypto/tls rejects.
	ModeZTLS
	// ModeOpenSSL shells out to the OpenSSL binary (s_client) and parses
	// its session output.
	ModeOpenSSL
)

// String returns the CLI-facing name of the mode: "auto", "ctls", "ztls",
// or "openssl". Modes outside the enumerated set render as "auto", the
// zero value's name.
//
// Returns:
//   - name (string): the mode's name.
func (m Mode) String() (name string) {
	switch m {
	case ModeAuto:
		name = "auto"
	case ModeCTLS:
		name = "ctls"
	case ModeZTLS:
		name = "ztls"
	case ModeOpenSSL:
		name = "openssl"
	default:
		name = "auto"
	}

	return name
}

// ParseMode converts a mode name into a [Mode]. It accepts "auto", "ctls",
// "ztls", and "openssl".
//
// Parameters:
//   - name (string): the mode name to parse.
//
// Returns:
//   - mode (Mode): the parsed mode; [ModeAuto] when name is empty.
//   - err (error): non-nil when name is not a recognized mode.
func ParseMode(name string) (mode Mode, err error) {
	switch strings.ToLower(name) {
	case "", "auto":
		mode = ModeAuto
	case "ctls":
		mode = ModeCTLS
	case "ztls":
		mode = ModeZTLS
	case "openssl":
		mode = ModeOpenSSL
	default:
		err = fmt.Errorf("probe.ParseMode: invalid input, unrecognized TLS connection mode: %q", name)

		return mode, err
	}

	return mode, nil
}
