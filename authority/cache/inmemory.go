package cache

import (
	"container/heap"
	"errors"
	"fmt"
	"sync"
)

// InMemory is a [CertificateCache] backed by an in-process map.
//
// It holds at most maxSize entries; when full and a new host is stored, the entry
// with the earliest CreatedAt is evicted (oldest-first). Entries are never expired
// eagerly: freshness is the authority's concern, and a stale entry is simply
// overwritten when the authority re-issues the certificate.
//
// InMemory is safe for concurrent use by multiple goroutines.
//
// Fields:
//   - mutex (sync.RWMutex): guards entries and byAge.
//   - entries (map[string]*heapEntry): the stored entries, keyed by normalized hostname.
//   - byAge (evictionHeap): the same entries as a min-heap ordered by CreatedAt, so
//     oldest-first eviction is O(log n) instead of a full scan of the cache.
//   - maxSize (int): the maximum number of entries held before eviction.
type InMemory struct {
	mutex   sync.RWMutex
	entries map[string]*heapEntry
	byAge   evictionHeap
	maxSize int
}

// Compile-time guard ensuring [InMemory] satisfies [CertificateCache].
var _ CertificateCache = (*InMemory)(nil)

// NewInMemory creates an in-memory certificate cache holding at most maxSize entries.
//
// Parameters:
//   - maxSize (int): the maximum number of entries held before oldest-first eviction;
//     must be positive (e.g., 1024).
//
// Returns:
//   - cache (*InMemory): the initialized in-memory cache.
//   - err (error): an error if maxSize is not positive; otherwise, nil.
func NewInMemory(maxSize int) (cache *InMemory, err error) {
	if maxSize <= 0 {
		err = fmt.Errorf("cache.NewInMemory: invalid input, cache max size must be positive, got %d", maxSize)

		return nil, err
	}

	cache = &InMemory{
		entries: make(map[string]*heapEntry),
		maxSize: maxSize,
	}

	return cache, nil
}

// Get returns the entry stored for the given host.
//
// The returned entry is the cache's stored entry and must not be mutated.
//
// Parameters:
//   - host (string): the normalized hostname to look up.
//
// Returns:
//   - entry (*CertificateCacheEntry): the stored entry, or nil when none is stored.
//   - found (bool): true when an entry is stored for host; otherwise, false.
func (c *InMemory) Get(host string) (entry *CertificateCacheEntry, found bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	stored, found := c.entries[host]
	if !found {
		return nil, false
	}

	return stored.entry, true
}

// Set stores an entry for the given host, replacing any existing entry.
//
// When the cache is full and the host is new, the entry with the earliest
// CreatedAt is evicted first. Storing an existing host never triggers eviction.
// Eviction pops the root of the byAge min-heap, so a full-cache Set is O(log n);
// see BenchmarkInMemorySetEvict.
//
// Parameters:
//   - host (string): the normalized hostname to store the entry under.
//   - entry (*CertificateCacheEntry): the entry to store.
//
// Returns:
//   - err (error): non-nil when entry is nil.
func (c *InMemory) Set(host string, entry *CertificateCacheEntry) (err error) {
	if entry == nil {
		return errors.New("cache.InMemory.Set: entry is nil")
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Replacing an existing host never triggers eviction; only its position in
	// the eviction order may change.
	if existing, exists := c.entries[host]; exists {
		existing.entry = entry

		heap.Fix(&c.byAge, existing.index)

		return nil
	}

	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	stored := &heapEntry{host: host, entry: entry}
	c.entries[host] = stored

	heap.Push(&c.byAge, stored)

	return nil
}

// evictOldest removes the entry with the earliest CreatedAt from the cache.
//
// It is called when the cache reaches its maximum size (maxSize) to make room
// for a new entry, and is a safe no-op on an empty cache. The oldest entry is
// the root of the byAge min-heap, so eviction is O(log n); entries with equal
// CreatedAt are evicted in arbitrary order, as before.
func (c *InMemory) evictOldest() {
	if len(c.byAge) == 0 {
		return
	}

	oldest := heap.Pop(&c.byAge).(*heapEntry)

	delete(c.entries, oldest.host)
}

// heapEntry pairs a cached certificate with its position in the eviction heap.
//
// Fields:
//   - host (string): the normalized hostname the entry is stored under.
//   - entry (*CertificateCacheEntry): the cached certificate bundle and its storage time.
//   - index (int): the entry's position in the byAge heap slice; meaningless once popped.
type heapEntry struct {
	host  string
	entry *CertificateCacheEntry
	index int
}

// evictionHeap is a min-heap of cache entries ordered by CreatedAt, oldest
// first. It implements heap.Interface for [InMemory]'s oldest-first eviction.
type evictionHeap []*heapEntry

// Len returns the number of entries in the heap.
//
// Returns:
//   - length (int): the number of entries in the heap.
func (h evictionHeap) Len() (length int) {
	return len(h)
}

// Less reports whether the entry at index i is older than the entry at index j.
//
// Parameters:
//   - i (int): the index of the first entry.
//   - j (int): the index of the second entry.
//
// Returns:
//   - less (bool): true if the entry at index i has the earlier CreatedAt; otherwise, false.
func (h evictionHeap) Less(i, j int) (less bool) {
	return h[i].entry.CreatedAt.Before(h[j].entry.CreatedAt)
}

// Swap exchanges the entries at indexes i and j, updating their heap positions.
//
// Parameters:
//   - i (int): the index of the first entry.
//   - j (int): the index of the second entry.
func (h evictionHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

// Push appends an entry to the heap. Unsupported values are ignored; Set uses
// concrete heapEntry values.
//
// Parameters:
//   - item (any): the *heapEntry to append; the heap only ever holds *heapEntry values.
func (h *evictionHeap) Push(item any) {
	stored, ok := item.(*heapEntry)
	if !ok {
		return
	}

	stored.index = len(*h)
	*h = append(*h, stored)
}

// Pop removes and returns the last entry in the heap slice.
//
// Returns:
//   - item (any): the removed *heapEntry.
func (h *evictionHeap) Pop() (item any) {
	old := *h
	length := len(old)
	stored := old[length-1]
	old[length-1] = nil // drop the reference so the popped entry can be collected
	stored.index = -1
	*h = old[:length-1]

	return stored
}

var _ CertificateCache = (*InMemory)(nil)
