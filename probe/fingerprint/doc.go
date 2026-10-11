// Package fingerprint computes TLS fingerprints — JA3 and JA3S — from
// captured handshake messages.
//
// The functions are pure: they take the raw handshake message bytes (the
// four-byte handshake header followed by the message body, as captured by
// the parent [probe] package) and return the canonical fingerprint
// segment; [Digest] reduces a segment to its MD5 hash. No I/O happens here,
// so the functions are trivially testable and reusable.
//
// GREASE values are handled per the JA3 specification: GREASE cipher
// suites, extensions, curves, and point formats are omitted from the
// fingerprint, since they are connection noise inserted deliberately.
//
// [probe]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/probe
package fingerprint
