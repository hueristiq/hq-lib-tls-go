// Package cache defines the certificate storage port used by the
// CertificateAuthority in the authority package, and provides ready-made
// implementations of it.
//
// # Entry points
//
// [NewInMemory] returns a bounded, concurrency-safe [InMemory] cache. A
// [CertificateCache] value is passed to the authority's WithCache option; the
// interface is small — Get and Set — so custom implementations are
// straightforward.
//
// # Concurrency
//
// Implementations must be safe for concurrent use: the authority calls Get
// and Set from multiple handshakes, though it never generates two certificates
// for the same host concurrently. [InMemory] guards its state with a mutex.
//
// The cache is pure storage. A CertificateAuthority has no cache by default
// and regenerates a certificate on every request; when a cache is configured,
// the authority itself decides whether a returned entry may still be served.
package cache
