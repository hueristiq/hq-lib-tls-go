// Package cert parses and analyzes X.509 certificate chains gathered by
// the parent probe package: subjects and issuers, validity, hostname
// coverage, digests, and validation against trust and revocation.
//
// The package works on raw DER chains (leaf first), the shape produced by
// [probe.Result], and has no dependency on the probe package itself.
// Parsing goes through zmap/zcrypto's tolerant x509 first and falls back
// to the standard library, so certificates that crypto/x509 rejects can
// still be inspected; trust and revocation checks deliberately use the
// standard library, because they ask "would a normal client accept this?"
// rather than "what does this say?".
//
// [probe.Result]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/probe#Result
package cert
