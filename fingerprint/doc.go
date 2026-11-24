// Package fingerprint computes TLS fingerprints: JA3, JA3S, and JARM.
//
// [JA3], [JA3S], and [Digest] are pure functions. They take the raw handshake
// message bytes (the four-byte handshake header followed by the message body,
// as captured by the tls package) and return canonical fingerprint segments or
// their MD5 digest. GREASE values are omitted per the JA3 specification.
//
// [JARM] dials the target and sends ten crafted ClientHello probes. It accepts
// a [Dialer] and timeout, opens independent connections, and does not share
// state with the pure fingerprint functions.
//
// # Concurrency
//
// [JA3], [JA3S], and [Digest] are pure and safe for concurrent use. [JARM]
// opens independent connections per call and is safe for concurrent use when
// the supplied dialer is.
//
// [tls]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go
package fingerprint
