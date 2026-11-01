// Package tls probes TLS servers and serves TLS connections. The root package
// is the client: it connects to TLS servers and captures negotiated parameters
// and certificates.
//
// # Entry points
//
// [New] creates a [Client]; [Client.Inspect] performs one connection and
// produces one [Result] that all analysis builds on, and [Client.JARM]
// computes a JARM fingerprint without completing a handshake.
//
// The connection itself runs in one of two modes:
//
//   - [ModeCTLS] — dial through the Go standard library's crypto/tls (the
//     default).
//   - [ModeOpenSSL] — shell out to the OpenSSL binary (s_client) and parse
//     its session output; requires openssl on PATH unless
//     [WithOpenSSLBinary] points elsewhere.
//
// The results carry no third-party types: certificates cross the package
// boundary as raw bytes, so every mode fills the same [Result] shape.
//
// # Packages
//
// The serving side and the analysis helpers live in focused subpackages:
//
//   - [authority] — generate certificate authorities, issue and sign X.509
//     certificates, and build SNI-driven tls.Config values.
//   - [certificate] — parse and analyze the certificates gathered by a probe:
//     subject and issuer fields, validity, hostname coverage, digests, and
//     validation against trust and revocation.
//   - [fingerprint] — JA3, JA3S, and JARM TLS fingerprints computed from
//     handshake message bytes supplied by the caller.
//   - [authority/cache] — the certificate storage port used by authority's
//     dynamic per-host issuance.
//
// # Configuration
//
// [OptionFunc] values passed to [New] configure the client: connection mode,
// timeout, SNI name, cipher suites, TLS version bounds, ALPN protocols, SOCKS5
// proxying, and the OpenSSL binary path. Unset options fall back to defaults
// ([ModeCTLS], a five-second timeout, and the openssl binary); invalid values
// make [New] return an error, and nil options are ignored. Because [Options] is exported, callers can write custom
// options. The [authority] package configures its own CA, leaf-certificate,
// TLS-config, and cache options.
//
// # Concurrency
//
// A [Client] is immutable after construction and safe for concurrent use;
// every method performs an independent connection. [authority.CertificateAuthority]
// and [cache.InMemory] are safe for concurrent use. Parsed certificate values
// are plain data owned by the caller.
//
// [authority]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/authority
// [certificate]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/certificate
// [fingerprint]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/fingerprint
// [authority.CertificateAuthority]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/authority#CertificateAuthority
// [authority/cache]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/authority/cache
// [cache.InMemory]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/authority/cache#InMemory
package tls
