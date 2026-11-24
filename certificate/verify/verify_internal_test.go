package verify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
)

func testCA(tb testing.TB, hosts []string) (caCertificate *x509.Certificate, caPrivateKey crypto.Signer, leafCertificate *x509.Certificate) {
	tb.Helper()

	caCertificate, caPrivateKey, err := hqgotlsauthority.GenerateCACertificatePrivateKey(
		hqgotlsauthority.WithCACommonName("cert test CA"),
		hqgotlsauthority.WithCAKeyType(hqgotlsauthority.KeyTypeECDSAP256),
	)

	require.NoError(tb, err)

	authority, err := hqgotlsauthority.New(caCertificate, caPrivateKey)

	require.NoError(tb, err)

	leafCertificate, _, err = authority.GenerateTLSCertificate(hosts)

	require.NoError(tb, err)

	return caCertificate, caPrivateKey, leafCertificate
}

func mintLeaf(tb testing.TB, caCertificate *x509.Certificate, caPrivateKey crypto.Signer, ocspServers, crlURLs []string) *x509.Certificate {
	tb.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	require.NoError(tb, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "revocation-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"revocation-test"},
		OCSPServer:            ocspServers,
		CRLDistributionPoints: crlURLs,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, caCertificate.PublicKey, caPrivateKey)

	require.NoError(tb, err)

	leaf, err := x509.ParseCertificate(der)

	require.NoError(tb, err)

	return leaf
}

func testHTTPClient() (client *http.Client) {
	return &http.Client{Timeout: 2 * time.Second}
}

func truncatedBodyServer(t *testing.T) (server *httptest.Server) {
	t.Helper()

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "10")

		_, _ = w.Write([]byte("abc"))
	}))

	t.Cleanup(server.Close)

	return server
}

func TestUntrusted(t *testing.T) {
	t.Parallel()

	// A chain signed by an ephemeral, unknown CA is untrusted to a client
	// with the system root store.
	caCertificate, _, leafCertificate := testCA(t, []string{"example.com"})

	untrusted, err := Untrusted([][]byte{leafCertificate.Raw, caCertificate.Raw}, "example.com")

	require.NoError(t, err)
	assert.True(t, untrusted)

	untrusted, err = Untrusted([][]byte{{0x00}}, "example.com")

	require.NoError(t, err)
	assert.True(t, untrusted, "unparseable certificates are untrusted")

	_, err = Untrusted(nil, "example.com")

	assert.Error(t, err)
}

func TestRevokedViaOCSP(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey, _ := testCA(t, []string{"example.com"})

	var responseDER []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")

		_, _ = w.Write(responseDER)
	}))

	defer server.Close()

	leaf := mintLeaf(t, caCertificate, caPrivateKey, []string{server.URL}, nil)

	template := ocsp.Response{
		Status:       ocsp.Revoked,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
	}

	responseDER, err := ocsp.CreateResponse(caCertificate, caCertificate, template, caPrivateKey)

	require.NoError(t, err)

	revoked, err := Revoked(context.Background(), [][]byte{leaf.Raw, caCertificate.Raw})

	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestNotRevokedViaOCSP(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey, _ := testCA(t, []string{"example.com"})

	var responseDER []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")

		_, _ = w.Write(responseDER)
	}))

	defer server.Close()

	leaf := mintLeaf(t, caCertificate, caPrivateKey, []string{server.URL}, nil)

	template := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
	}

	responseDER, err := ocsp.CreateResponse(caCertificate, caCertificate, template, caPrivateKey)

	require.NoError(t, err)

	revoked, err := Revoked(context.Background(), [][]byte{leaf.Raw, caCertificate.Raw})

	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestRevokedViaCRL(t *testing.T) {
	t.Parallel()

	// The CRL issuer needs the crlSign key usage, which the shared test CA
	// deliberately lacks (it only signs certificates).
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CRL test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)

	require.NoError(t, err)

	caCertificate, err := x509.ParseCertificate(caDER)

	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("placeholder"))
	}))

	defer server.Close()

	leaf := mintLeaf(t, caCertificate, caKey, nil, []string{server.URL})

	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now()},
		},
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(time.Hour),
	}, caCertificate, caKey)

	require.NoError(t, err)

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(crl)
	})

	revoked, err := Revoked(context.Background(), [][]byte{leaf.Raw, caCertificate.Raw})

	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestRevokedWithoutSources(t *testing.T) {
	t.Parallel()

	caCertificate, _, leafCertificate := testCA(t, []string{"example.com"})

	revoked, err := Revoked(context.Background(), [][]byte{leafCertificate.Raw, caCertificate.Raw})

	require.NoError(t, err)
	assert.False(t, revoked, "no revocation sources yields no revocation verdict")
}

func TestUntrustedWithTrustedRoot(t *testing.T) {
	t.Parallel()

	caCertificate, _, leafCertificate := testCA(t, []string{"example.com"})

	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)

	untrusted, err := untrustedWith([][]byte{leafCertificate.Raw, caCertificate.Raw}, "example.com:443", roots)
	require.NoError(t, err)
	assert.False(t, untrusted, "a chain signed by a trusted root verifies")

	untrusted, err = untrustedWith([][]byte{leafCertificate.Raw, caCertificate.Raw}, "other.example.com", roots)
	require.NoError(t, err)
	assert.True(t, untrusted, "a hostname mismatch fails verification")
}

func TestUntrustedIgnoresUnparseableIntermediate(t *testing.T) {
	t.Parallel()

	caCertificate, _, leafCertificate := testCA(t, []string{"example.com"})

	untrusted, err := untrustedWith([][]byte{leafCertificate.Raw, {0x00}, caCertificate.Raw}, "example.com", x509.NewCertPool())
	require.NoError(t, err)
	assert.True(t, untrusted)
}

func TestRevokedValidation(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey, leafCertificate := testCA(t, []string{"example.com"})

	_, err := Revoked(context.Background(), nil)
	require.ErrorContains(t, err, "certificate chain is empty")

	_, err = Revoked(context.Background(), [][]byte{{0x00}})
	require.ErrorContains(t, err, "parsing leaf certificate")

	_, err = Revoked(context.Background(), [][]byte{leafCertificate.Raw, {0x00}})
	require.ErrorContains(t, err, "parsing issuer certificate")

	unreachable := []string{"http://127.0.0.1:1"}

	withUnreachableOCSP := mintLeaf(t, caCertificate, caPrivateKey, unreachable, nil)
	revoked, err := Revoked(context.Background(), [][]byte{withUnreachableOCSP.Raw, caCertificate.Raw})
	require.NoError(t, err)
	assert.False(t, revoked, "an unreachable OCSP responder is skipped")

	withUnreachableCRL := mintLeaf(t, caCertificate, caPrivateKey, nil, unreachable)
	revoked, err = Revoked(context.Background(), [][]byte{withUnreachableCRL.Raw, caCertificate.Raw})
	require.NoError(t, err)
	assert.False(t, revoked, "an unreachable CRL is skipped")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	revoked, err = Revoked(ctx, [][]byte{withUnreachableOCSP.Raw, caCertificate.Raw})
	require.NoError(t, err)
	assert.False(t, revoked, "a canceled context skips the responder")
}

func TestRevokedUnknownOCSPStatusFallsThrough(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey, _ := testCA(t, []string{"example.com"})

	var responseDER []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")

		_, _ = w.Write(responseDER)
	}))

	defer server.Close()

	leaf := mintLeaf(t, caCertificate, caPrivateKey, []string{server.URL}, nil)

	template := ocsp.Response{
		Status:       ocsp.Unknown,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
	}

	responseDER, err := ocsp.CreateResponse(caCertificate, caCertificate, template, caPrivateKey)
	require.NoError(t, err)

	revoked, err := Revoked(context.Background(), [][]byte{leaf.Raw, caCertificate.Raw})
	require.NoError(t, err)
	assert.False(t, revoked, "an unknown status is inconclusive")
}

func TestFetchOCSPStatusFailurePaths(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey, _ := testCA(t, []string{"example.com"})

	leaf := mintLeaf(t, caCertificate, caPrivateKey, nil, nil)
	client := testHTTPClient()

	t.Run("unsupported request", func(t *testing.T) {
		t.Parallel()

		brokenIssuer := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("broken")}

		_, err := fetchOCSPStatus(context.Background(), client, leaf, brokenIssuer, "http://example.com")
		require.ErrorContains(t, err, "creating OCSP request")
	})

	t.Run("invalid URL", func(t *testing.T) {
		t.Parallel()

		_, err := fetchOCSPStatus(context.Background(), client, leaf, caCertificate, "://bad")
		require.ErrorContains(t, err, "building OCSP request")
	})

	t.Run("transport failure", func(t *testing.T) {
		t.Parallel()

		_, err := fetchOCSPStatus(context.Background(), client, leaf, caCertificate, "http://127.0.0.1:1")
		require.ErrorContains(t, err, "posting OCSP request")
	})

	t.Run("truncated body", func(t *testing.T) {
		t.Parallel()

		server := truncatedBodyServer(t)

		_, err := fetchOCSPStatus(context.Background(), client, leaf, caCertificate, server.URL)
		require.ErrorContains(t, err, "reading OCSP response")
	})

	t.Run("malformed response", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not an OCSP response"))
		}))
		defer server.Close()

		_, err := fetchOCSPStatus(context.Background(), client, leaf, caCertificate, server.URL)
		require.ErrorContains(t, err, "parsing OCSP response")
	})
}

func TestCRLRevokesFailurePaths(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey, _ := testCA(t, []string{"example.com"})

	leaf := mintLeaf(t, caCertificate, caPrivateKey, nil, nil)
	client := testHTTPClient()

	t.Run("invalid URL", func(t *testing.T) {
		t.Parallel()

		_, err := crlRevokes(context.Background(), client, leaf, "://bad")
		require.ErrorContains(t, err, "building CRL request")
	})

	t.Run("transport failure", func(t *testing.T) {
		t.Parallel()

		_, err := crlRevokes(context.Background(), client, leaf, "http://127.0.0.1:1")
		require.ErrorContains(t, err, "fetching CRL")
	})

	t.Run("truncated body", func(t *testing.T) {
		t.Parallel()

		server := truncatedBodyServer(t)

		_, err := crlRevokes(context.Background(), client, leaf, server.URL)
		require.ErrorContains(t, err, "reading CRL")
	})

	t.Run("malformed CRL", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not a CRL"))
		}))
		defer server.Close()

		_, err := crlRevokes(context.Background(), client, leaf, server.URL)
		require.ErrorContains(t, err, "parsing CRL")
	})

	t.Run("not revoked", func(t *testing.T) {
		t.Parallel()

		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "CRL test CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}

		caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		require.NoError(t, err)

		crlCA, err := x509.ParseCertificate(caDER)
		require.NoError(t, err)

		crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().Add(time.Hour),
		}, crlCA, caKey)
		require.NoError(t, err)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(crl)
		}))
		defer server.Close()

		revoked, err := crlRevokes(context.Background(), client, leaf, server.URL)
		require.NoError(t, err)
		assert.False(t, revoked, "a CRL without the leaf's serial does not revoke it")
	})
}

func TestVerifyAndLoadCAPool(t *testing.T) {
	t.Parallel()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCertificate, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)

	require.NoError(t, Verify([][]byte{leafDER}, "example.com", roots))
	require.Error(t, Verify([][]byte{leafDER}, "other.example", roots))
	require.Error(t, Verify(nil, "example.com", roots))

	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))

	pool, err := LoadCAPool(path)
	require.NoError(t, err)
	require.NotNil(t, pool)
}
