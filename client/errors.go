package client

import (
	"fmt"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// Matchable failure classes of the TLS client.
const (
	// ErrHandshake reports a failed TLS handshake.
	ErrHandshake hqgoerrors.Sentinel = "handshake failed"
	// ErrUnsupportedVersion reports a protocol version the engine does not
	// implement.
	ErrUnsupportedVersion hqgoerrors.Sentinel = "unsupported protocol version"
	// ErrUnsupportedCipherSuite reports a cipher suite the engine cannot
	// complete a handshake with.
	ErrUnsupportedCipherSuite hqgoerrors.Sentinel = "unsupported cipher suite"
	// ErrExportCipherSuitesDisabled reports an export suite configured without
	// AllowExportCipherSuites.
	ErrExportCipherSuitesDisabled hqgoerrors.Sentinel = "export cipher suites are disabled"
	// ErrInvalidClientHelloSpec reports a HelloSpec missing required
	// extensions for the configured versions.
	ErrInvalidClientHelloSpec hqgoerrors.Sentinel = "invalid ClientHello spec"
	// ErrNoCertificates reports that the peer sent no certificate chain.
	ErrNoCertificates hqgoerrors.Sentinel = "peer sent no certificates"
	// ErrVerifyFailed reports a failed certificate or handshake signature
	// verification.
	ErrVerifyFailed hqgoerrors.Sentinel = "verification failed"
	// ErrAlert reports a fatal TLS alert received from the peer.
	ErrAlert hqgoerrors.Sentinel = "peer sent an alert"
)

// AlertError is a TLS alert received from the peer.
type AlertError struct {
	// Level is the alert level (1 warning, 2 fatal).
	Level uint8
	// Description is the alert description code.
	Description uint8
}

// Error renders the alert.
func (e *AlertError) Error() (message string) {
	return fmt.Sprintf("peer alert: %s (%s, level %d)", alertDescriptionText(e.Description), alertLevelText(e.Level), e.Level)
}

// Is reports whether target is ErrAlert.
func (e *AlertError) Is(target error) (match bool) {
	return target == ErrAlert
}
