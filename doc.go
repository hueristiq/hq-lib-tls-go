// Package tls probes TLS servers: it connects, captures the negotiated
// parameters and certificate chain, and exposes the decrypted handshake
// trace.
//
// # Entry points
//
// [New] creates a [Client]; [Client.Inspect] performs one connection and
// produces one [Result] that all analysis builds on. [Client.JARM] computes a
// JARM fingerprint without completing a handshake, and
// [Client.EnumerateVersions] / [Client.EnumerateCipherSuites] probe the
// server's supported versions and cipher suites.
//
// The connections run through the native engine in the [client] subpackage. That
// engine speaks SSL 3.0 through TLS 1.3, including export cipher suites, and
// logs every handshake message in plaintext. There is no separate connection
// mode: client.Config selects the protocol range and suites directly.
//
// # Configuration
//
// [OptionFunc] values passed to [New] configure the client: timeout, SNI, cipher
// suites, TLS version bounds, ALPN protocols, SOCKS5 proxying, certificate
// verification, export suites, handshake logging, and a full client.Config or
// HelloSpec. Unset options fall back to defaults (a five-second timeout
// and TLS 1.2 through TLS 1.3 with secure suites). Invalid values make [New]
// return an error, and nil options are ignored. Because [Options] is exported,
// callers can write custom options.
//
// # Results
//
// [Result] carries the host and peer IP, negotiated version and cipher, ALPN
// protocol, DER certificate chain, parsed [certificate.Report], and the
// decrypted handshake trace. Certificate analysis, fingerprints, and
// enumeration build on this shape.
//
// # Packages
//
// The serving side and the analysis helpers live in focused subpackages:
//
//   - [client] — the native client engine: Config, Conn, Dial, ConnectionState,
//     HelloSpec, and handshake logging.
//   - [ciphers] — cipher suite metadata, names, security classes, and parsing.
//   - [authority] — generate certificate authorities, issue and sign X.509
//     certificates, and build SNI-driven tls.Config values for servers.
//   - [certificate] — parse and analyze the certificates gathered by a probe:
//     subject and issuer fields, validity, hostname coverage, digests, and
//     scanner metadata.
//   - [certificate/verify] — trust and revocation checks against root stores,
//     OCSP responders, and CRL distribution points.
//   - [fingerprint] — JA3, JA3S, and JARM fingerprints. JARM accepts a dialer
//     and timeout; [Client.JARM] delegates to it with the probe's settings.
//   - [authority/cache] — the certificate storage port used by authority's
//     dynamic per-host issuance.
//
// # Concurrency
//
// A [Client] is immutable after construction and safe for concurrent use;
// every method performs an independent connection.
// [authority.CA] and [cache.InMemory] are safe for
// concurrent use. Parsed certificate values are plain data owned by the
// caller.
//
// [client]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/client
// [ciphers]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/ciphers
// [authority]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/authority
// [certificate]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/certificate
// [certificate/verify]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/certificate/verify
// [fingerprint]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/fingerprint
// [authority.CA]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/authority#CA
// [authority/cache]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/authority/cache
// [cache.InMemory]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/authority/cache#InMemory
package tls
