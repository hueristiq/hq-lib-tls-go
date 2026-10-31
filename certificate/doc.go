// Package certificate parses and analyzes X.509 certificate chains gathered by
// the root package: subjects and issuers, validity, hostname coverage,
// digests, and validation against trust and revocation.
//
// The package works on raw DER chains (leaf first), the shape produced by
// [Result], and has no dependency on the root package itself.
// Parsing goes through zmap/zcrypto's tolerant x509 first and falls back
// to the standard library, so certificates that crypto/x509 rejects can
// still be inspected; trust and revocation checks deliberately use the
// standard library, because they ask "would a normal client accept this?"
// rather than "what does this say?".
//
// # Entry points
//
// [Parse] turns a DER chain into [Certificate] values. The Certificate methods
// report digests ([Certificate.MD5], [Certificate.SHA1], [Certificate.SHA256]),
// validity ([Certificate.Expired]), hostname coverage
// ([Certificate.CoversHost]), and PEM encoding ([Certificate.PEMBlock]).
// [Untrusted] and [Revoked] run trust and revocation checks against the
// standard library's verifier and the chain's OCSP and CRL endpoints.
//
// # Concurrency
//
// [Parse] and the Certificate methods are pure and safe for concurrent use;
// [Certificate] values are immutable after parsing.
//
// [Result]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go#Result
package certificate
