// Package certificate parses and analyzes X.509 certificate chains gathered by
// the root package: subjects and issuers, validity, hostname coverage, and
// digests. Trust and revocation checks live in the verify subpackage.
//
// The package works on raw DER chains, leaf first, the shape produced by
// [Result], and has no dependency on the root package itself. Parsing uses the
// standard library's crypto/x509.
//
// # Entry points
//
// [Parse] turns a DER chain into [Cert] values. The Cert methods report digests
// ([Cert.MD5], [Cert.SHA1], [Cert.SHA256]), validity ([Cert.Expired]),
// hostname coverage ([Cert.CoversHost]), and PEM encoding ([Cert.PEMBlock]).
// [Analyze] builds a [Report] with the metadata commonly emitted by scanners.
// The verify subpackage provides the trust and revocation checks.
//
// # Concurrency
//
// [Parse] and the Cert methods are pure and safe for concurrent use; [Cert]
// values are immutable after parsing.
//
// [Result]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go#Result
//
// [verify]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/certificate/verify
package certificate
