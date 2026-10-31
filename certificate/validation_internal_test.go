package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// mintLeaf issues a leaf whose AIA extension carries the given OCSP and
// CRL URLs.
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

func TestExpired(t *testing.T) {
	t.Parallel()

	_, _, leafCertificate := testCA(t, []string{"example.com"})

	leaf, err := Parse([][]byte{leafCertificate.Raw})

	require.NoError(t, err)

	assert.False(t, leaf[0].Expired(time.Now()))
	assert.False(t, leaf[0].Expired(leaf[0].NotBefore))
	assert.True(t, leaf[0].Expired(leaf[0].NotAfter.Add(time.Second)))
	assert.False(t, (*Certificate)(nil).Expired(time.Now()))
}

func TestSelfSigned(t *testing.T) {
	t.Parallel()

	caCertificate, _, leafCertificate := testCA(t, []string{"example.com"})

	chain, err := Parse([][]byte{leafCertificate.Raw, caCertificate.Raw})

	require.NoError(t, err)

	assert.False(t, chain[0].SelfSigned())
	assert.True(t, chain[1].SelfSigned())
}

func TestMismatched(t *testing.T) {
	t.Parallel()

	_, _, leafCertificate := testCA(t, []string{"example.com"})

	leaf, err := Parse([][]byte{leafCertificate.Raw})

	require.NoError(t, err)

	assert.False(t, leaf[0].Mismatched("example.com"))
	assert.True(t, leaf[0].Mismatched("other.org"))
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

	revoked, err := Revoked([][]byte{leaf.Raw, caCertificate.Raw})

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

	revoked, err := Revoked([][]byte{leaf.Raw, caCertificate.Raw})

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

	revoked, err := Revoked([][]byte{leaf.Raw, caCertificate.Raw})

	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestRevokedWithoutSources(t *testing.T) {
	t.Parallel()

	caCertificate, _, leafCertificate := testCA(t, []string{"example.com"})

	revoked, err := Revoked([][]byte{leafCertificate.Raw, caCertificate.Raw})

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

func TestSelfSignedNilReceiver(t *testing.T) {
	t.Parallel()

	assert.False(t, (*Certificate)(nil).SelfSigned())
}

func TestRevokedValidation(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey, leafCertificate := testCA(t, []string{"example.com"})

	_, err := Revoked(nil)
	require.ErrorContains(t, err, "certificate chain is empty")

	_, err = Revoked([][]byte{{0x00}})
	require.ErrorContains(t, err, "parsing leaf certificate")

	_, err = Revoked([][]byte{leafCertificate.Raw, {0x00}})
	require.ErrorContains(t, err, "parsing issuer certificate")

	unreachable := []string{"http://127.0.0.1:1"}

	withUnreachableOCSP := mintLeaf(t, caCertificate, caPrivateKey, unreachable, nil)
	revoked, err := Revoked([][]byte{withUnreachableOCSP.Raw, caCertificate.Raw})
	require.NoError(t, err)
	assert.False(t, revoked, "an unreachable OCSP responder is skipped")

	withUnreachableCRL := mintLeaf(t, caCertificate, caPrivateKey, nil, unreachable)
	revoked, err = Revoked([][]byte{withUnreachableCRL.Raw, caCertificate.Raw})
	require.NoError(t, err)
	assert.False(t, revoked, "an unreachable CRL is skipped")
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

	revoked, err := Revoked([][]byte{leaf.Raw, caCertificate.Raw})
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

		_, err := fetchOCSPStatus(client, leaf, brokenIssuer, "http://example.com")
		require.ErrorContains(t, err, "creating OCSP request")
	})

	t.Run("invalid URL", func(t *testing.T) {
		t.Parallel()

		_, err := fetchOCSPStatus(client, leaf, caCertificate, "://bad")
		require.ErrorContains(t, err, "building OCSP request")
	})

	t.Run("transport failure", func(t *testing.T) {
		t.Parallel()

		_, err := fetchOCSPStatus(client, leaf, caCertificate, "http://127.0.0.1:1")
		require.ErrorContains(t, err, "posting OCSP request")
	})

	t.Run("truncated body", func(t *testing.T) {
		t.Parallel()

		server := truncatedBodyServer(t)

		_, err := fetchOCSPStatus(client, leaf, caCertificate, server.URL)
		require.ErrorContains(t, err, "reading OCSP response")
	})

	t.Run("malformed response", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not an OCSP response"))
		}))
		defer server.Close()

		_, err := fetchOCSPStatus(client, leaf, caCertificate, server.URL)
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

		_, err := crlRevokes(client, leaf, "://bad")
		require.ErrorContains(t, err, "building CRL request")
	})

	t.Run("transport failure", func(t *testing.T) {
		t.Parallel()

		_, err := crlRevokes(client, leaf, "http://127.0.0.1:1")
		require.ErrorContains(t, err, "fetching CRL")
	})

	t.Run("truncated body", func(t *testing.T) {
		t.Parallel()

		server := truncatedBodyServer(t)

		_, err := crlRevokes(client, leaf, server.URL)
		require.ErrorContains(t, err, "reading CRL")
	})

	t.Run("malformed CRL", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not a CRL"))
		}))
		defer server.Close()

		_, err := crlRevokes(client, leaf, server.URL)
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

		revoked, err := crlRevokes(client, leaf, server.URL)
		require.NoError(t, err)
		assert.False(t, revoked, "a CRL without the leaf's serial does not revoke it")
	})
}
