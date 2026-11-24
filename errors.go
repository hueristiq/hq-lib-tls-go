package tlsprobe

import (
	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// Matchable failure classes of the probing modes.
const (
	// ErrHandshake reports a failed TLS handshake with the target.
	ErrHandshake hqgoerrors.Sentinel = "handshake failed"
	// ErrOpenSSLUnavailable reports that the OpenSSL binary required by
	// [ModeOpenSSL] could not be executed or produced no session output.
	ErrOpenSSLUnavailable hqgoerrors.Sentinel = "openssl unavailable"
)
