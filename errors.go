package tls

import (
	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// Matchable failure classes of the probing client.
const (
	// ErrHandshake reports a failed TLS handshake with the target.
	ErrHandshake hqgoerrors.Sentinel = "handshake failed"
)
