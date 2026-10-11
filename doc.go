// Package tls provides TLS serving and probing primitives for Go programs,
// organized into focused subpackages.
//
// # Subpackages
//
//   - [authority] — the server side: generate certificate authorities, issue
//     and sign X.509 certificates, and build SNI-driven tls.Config values.
//   - [probe] — the client side: connect to TLS servers through stdlib
//     crypto/tls, zmap/zcrypto, or the OpenSSL binary, capturing certificates
//     and handshake data in one unified result.
//   - [probe/fingerprint] — JA3, JA3S, and JARM TLS fingerprints computed from
//     captured handshake messages.
//   - [cert] — parse and analyze the certificates gathered by probe:
//     subject and issuer fields, validity, hostname coverage, digests, and
//     validation against trust and revocation.
//   - [cache] — the certificate storage port used by authority's dynamic
//     per-host issuance.
//
// [authority]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/authority
// [probe]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/probe
// [probe/fingerprint]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/probe/fingerprint
// [cert]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/cert
// [cache]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/cache
package tls
