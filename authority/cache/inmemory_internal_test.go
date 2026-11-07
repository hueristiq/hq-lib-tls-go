package cache

import (
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInMemoryRejectsNonPositiveMaxSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		maxSize int
	}{
		{"zero max size", 0},
		{"negative max size", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cache, err := NewInMemory(tt.maxSize)
			require.ErrorContains(t, err, "cache max size must be positive")
			assert.Nil(t, cache)
		})
	}
}

func TestInMemorySetGetRoundtrip(t *testing.T) {
	t.Parallel()

	c, err := NewInMemory(2)
	require.NoError(t, err)

	entry := &CertificateCacheEntry{
		Certificate: &tls.Certificate{},
		CreatedAt:   time.Now(),
	}

	setCertificate(t, c, "example.com", entry)

	got, found := c.Get("example.com")
	require.True(t, found)
	assert.Same(t, entry, got)
}

func TestInMemoryGetMissOnUnknownHost(t *testing.T) {
	t.Parallel()

	c, err := NewInMemory(2)
	require.NoError(t, err)

	setCertificate(t, c, "example.com", &CertificateCacheEntry{CreatedAt: time.Now()})

	entry, found := c.Get("unknown.example.com")
	assert.False(t, found)
	assert.Nil(t, entry)
}

func TestInMemorySetRejectsNilEntry(t *testing.T) {
	t.Parallel()

	c, err := NewInMemory(1)
	require.NoError(t, err)

	err = c.Set("example.com", nil)
	require.EqualError(t, err, "cache.InMemory.Set: entry is nil")
}

func TestEvictionHeapPushIgnoresWrongType(t *testing.T) {
	t.Parallel()

	var h evictionHeap

	h.Push("not a heap entry")
	assert.Zero(t, h.Len())
}

func TestInMemoryEvictsOldestEntryWhenFull(t *testing.T) {
	t.Parallel()

	c, err := NewInMemory(2)
	require.NoError(t, err)

	now := time.Now()

	setCertificate(t, c, "oldest.example.com", &CertificateCacheEntry{CreatedAt: now.Add(-3 * time.Hour)})
	setCertificate(t, c, "newest.example.com", &CertificateCacheEntry{CreatedAt: now.Add(-time.Hour)})

	setCertificate(t, c, "added.example.com", &CertificateCacheEntry{CreatedAt: now})

	_, found := c.Get("oldest.example.com")
	assert.False(t, found)

	_, found = c.Get("newest.example.com")
	assert.True(t, found)

	_, found = c.Get("added.example.com")
	assert.True(t, found)
}

func TestInMemoryEvictOldestOnEmptyCacheIsNoOp(t *testing.T) {
	t.Parallel()

	c, err := NewInMemory(1)
	require.NoError(t, err)

	c.evictOldest()

	_, found := c.Get("example.com")
	assert.False(t, found)
}

func TestInMemorySetExistingHostOverwritesWithoutEviction(t *testing.T) {
	t.Parallel()

	c, err := NewInMemory(2)
	require.NoError(t, err)

	now := time.Now()

	setCertificate(t, c, "a.example.com", &CertificateCacheEntry{CreatedAt: now.Add(-3 * time.Hour)})
	setCertificate(t, c, "b.example.com", &CertificateCacheEntry{CreatedAt: now.Add(-time.Hour)})

	replacement := &CertificateCacheEntry{
		Certificate: &tls.Certificate{},
		CreatedAt:   now,
	}

	setCertificate(t, c, "a.example.com", replacement)

	got, found := c.Get("a.example.com")
	require.True(t, found)
	assert.Same(t, replacement, got)

	_, found = c.Get("b.example.com")
	assert.True(t, found)
}

func TestInMemoryConcurrentGetSet(t *testing.T) {
	t.Parallel()

	c, err := NewInMemory(2)
	require.NoError(t, err)

	hosts := []string{"a.example.com", "b.example.com", "c.example.com"}

	var wg sync.WaitGroup

	for i := range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for j := range 100 {
				host := hosts[(i+j)%len(hosts)]

				setCertificate(t, c, host, &CertificateCacheEntry{CreatedAt: time.Now()})

				_, _ = c.Get(host)
			}
		}()
	}

	wg.Wait()
}

func setCertificate(t *testing.T, c *InMemory, host string, entry *CertificateCacheEntry) {
	t.Helper()
	assert.NoError(t, c.Set(host, entry))
}
