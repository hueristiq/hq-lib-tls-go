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

// CertificateCache defines the contract for storing dynamically generated
// certificates, keyed by normalized hostname.
//
// Implementations provide pure storage: the authority decides whether a
// returned entry may be served (maximum age and leaf expiry), so a cache
// cannot get certificate validity wrong. Get runs on every TLS handshake and
// must be cheap; Set may evict entries at its own discretion. A miss is
// reported as a nil entry with found false, not as an error; Set rejects a nil
// entry with an error. The first Set for a host installs the entry, later ones
// replace it.
//
// Implementations must be safe for concurrent use. The authority never calls
// Set concurrently for the same host (in-flight generation is deduplicated),
// but concurrent Get and Set calls for different hosts are expected.
//
// Callers must not mutate entries returned by Get: implementations hand out
// their stored entries, and the authority relies on their contents. Likewise,
// the cache may keep the entry passed to Set rather than copying it, so the
// caller must not mutate it afterwards either. The package ships [InMemory];
// the authority accepts any implementation through its configuration.
type CertificateCache interface {
	// Get returns the entry stored for host.
	//
	// The call must not block on certificate generation or network I/O: a
	// miss is a normal result, reported through found rather than an error.
	//
	// Parameters:
	//   - host (string): the normalized hostname to look up.
	//
	// Returns:
	//   - entry (*CertificateCacheEntry): the stored entry, or nil when none
	//     is stored.
	//   - found (bool): true when an entry is stored for host; false
	//     otherwise, in which case entry is nil.
	Get(host string) (entry *CertificateCacheEntry, found bool)

	// Set stores entry for host, replacing any existing entry.
	//
	// Implementations may evict entries at their own discretion and may keep
	// entry rather than copying it; the caller must not mutate it afterwards.
	//
	// Parameters:
	//   - host (string): the normalized hostname to store the entry under.
	//   - entry (*CertificateCacheEntry): the entry to store; must not be nil.
	//
	// Returns:
	//   - err (error): non-nil when entry is nil or storage fails.
	Set(host string, entry *CertificateCacheEntry) (err error)
}
