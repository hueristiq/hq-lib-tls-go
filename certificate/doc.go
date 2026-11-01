// Package certificate parses and analyzes X.509 certificate chains gathered by
// the root package: subjects and issuers, validity, hostname coverage,
// digests, and validation against trust and revocation.
//
// The package works on raw DER chains (leaf first), the shape produced by
// [Result], and has no dependency on the root package itself.
// Parsing uses the standard library's crypto/x509, like the trust and
// revocation checks: it asks "would a normal client accept this?" rather
// than trying to decode malformed certificates.
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
