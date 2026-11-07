package cache_test

import (
	"crypto/tls"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	hqgotlscache "github.com/hueristiq/hq-lib-tls-go/authority/cache"
)

func BenchmarkInMemorySetEvict(b *testing.B) {
	const maxSize = 1024

	cache, err := hqgotlscache.NewInMemory(maxSize)
	require.NoError(b, err)

	entry := &hqgotlscache.CertificateCacheEntry{
		Certificate: &tls.Certificate{},
		CreatedAt:   time.Now(),
	}

	for i := range maxSize {
		cache.Set(strconv.Itoa(i)+".example.com", entry)
	}

	b.ReportAllocs()

	i := maxSize

	for b.Loop() {
		cache.Set(strconv.Itoa(i)+".example.com", entry)
		i++
	}
}
