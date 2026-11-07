package authority_test

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
	hqgotlscache "github.com/hueristiq/hq-lib-tls-go/authority/cache"
)

func BenchmarkGetCertificateCacheHit(b *testing.B) {
	caCertificate, caPrivateKey, err := hqgotlsauthority.GenerateCACertificatePrivateKey(
		hqgotlsauthority.WithCACommonName("Benchmark CA"),
		hqgotlsauthority.WithCAKeyType(hqgotlsauthority.KeyTypeECDSAP256),
	)
	require.NoError(b, err)

	certificateCache, err := hqgotlscache.NewInMemory(8)
	require.NoError(b, err)

	ca, err := hqgotlsauthority.New(caCertificate, caPrivateKey, hqgotlsauthority.WithCache(certificateCache))
	require.NoError(b, err)

	config := ca.NewTLSConfig()
	hello := &tls.ClientHelloInfo{ServerName: "example.com"}

	_, err = config.GetCertificate(hello)
	require.NoError(b, err)

	b.ReportAllocs()

	for b.Loop() {
		certificate, err := config.GetCertificate(hello)
		require.NoError(b, err)
		require.NotNil(b, certificate)
	}
}
