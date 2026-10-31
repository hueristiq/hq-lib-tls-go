package cache

import (
	"crypto/tls"
	"time"
)

// CertificateCacheEntry is a cached TLS certificate bundle and its storage time.
//
// Fields:
//   - Certificate (*tls.Certificate): the cached certificate bundle (leaf plus CA chain).
//   - CreatedAt (time.Time): when the entry was stored; the authority compares it against
//     its maximum cache age, and [InMemory] uses it for oldest-first eviction.
type CertificateCacheEntry struct {
	Certificate *tls.Certificate
	CreatedAt   time.Time
}

// CertificateCache stores dynamically generated certificates keyed by normalized hostname.
//
// Implementations must be safe for concurrent use. The authority never calls Set
// concurrently for the same host (in-flight generation is deduplicated), but concurrent
// Get and Set calls for different hosts are expected.
//
// The cache is pure storage: the authority decides whether a returned entry may be
// served (maximum age and leaf expiry), so implementations cannot get certificate
// validity wrong. Get runs on every TLS handshake and must be cheap.
//
// Callers must not mutate entries returned by Get: implementations hand out their
// stored entries, and the authority relies on their contents.
//
// Methods are listed below with their contracts.
type CertificateCache interface {
	// Get returns the entry stored for host.
	//
	// Parameters:
	//   - host (string): the normalized hostname to look up.
	//
	// Returns:
	//   - entry (*CertificateCacheEntry): the stored entry, or nil when none is stored.
	//   - found (bool): true when an entry is stored for host; otherwise, false.
	Get(host string) (entry *CertificateCacheEntry, found bool)

	// Set stores entry for host, replacing any existing entry. Implementations
	// may evict entries at their own discretion.
	//
	// Parameters:
	//   - host (string): the normalized hostname to store the entry under.
	//   - entry (*CertificateCacheEntry): the entry to store; must not be nil.
	Set(host string, entry *CertificateCacheEntry)
}
