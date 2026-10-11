package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec // G501: the test verifies the package's MD5 digest.
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: the test verifies the package's SHA-1 digest.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
)

// testCA mints a CA and an authority-issued leaf for the given hosts.
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

func TestParse(t *testing.T) {
	t.Parallel()

	caCertificate, _, leafCertificate := testCA(t, []string{"example.com", "*.example.com"})

	certificates, err := Parse([][]byte{leafCertificate.Raw, caCertificate.Raw})

	require.NoError(t, err)
	require.Len(t, certificates, 2)

	leaf := certificates[0]

	assert.Equal(t, "example.com", leaf.Subject.CommonName)
	assert.Equal(t, "cert test CA", leaf.Issuer.CommonName)
	assert.Equal(t, leafCertificate.SerialNumber.String(), leaf.SerialNumber)
	assert.Equal(t, []string{"example.com", "*.example.com"}, leaf.DNSNames)
	assert.Equal(t, leafCertificate.Raw, leaf.Raw)
	assert.Equal(t, "cert test CA", certificates[1].Subject.CommonName)
}

func TestParseEmpty(t *testing.T) {
	t.Parallel()

	_, err := Parse(nil)

	require.Error(t, err)

	_, err = Parse([][]byte{})

	require.Error(t, err)

	_, err = Parse([][]byte{{0x00}})

	require.Error(t, err, "unparseable certificates are rejected")
}

func TestCoversHost(t *testing.T) {
	t.Parallel()

	_, _, leafCertificate := testCA(t, []string{"example.com", "*.example.com", "10.0.0.1"})

	leaf, err := Parse([][]byte{leafCertificate.Raw})

	require.NoError(t, err)
	require.Len(t, leaf, 1)

	certificate := leaf[0]

	tests := map[string]bool{
		"example.com":     true,
		"EXAMPLE.COM":     true,
		"example.com.":    true,
		"example.com:443": true,
		"www.example.com": true,
		"a.b.example.com": false,
		"badexample.com":  false,
		"other.org":       false,
		"10.0.0.1":        true,
		"10.0.0.2":        false,
	}

	for host, expected := range tests {
		t.Run(host, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, expected, certificate.CoversHost(host))
		})
	}

	assert.False(t, (*Certificate)(nil).CoversHost("example.com"))
}

func TestHashes(t *testing.T) {
	t.Parallel()

	_, _, leafCertificate := testCA(t, []string{"example.com"})

	leaf, err := Parse([][]byte{leafCertificate.Raw})

	require.NoError(t, err)

	certificate := leaf[0]

	md5Sum := md5.Sum(leafCertificate.Raw)   //nolint:gosec // G401: the test verifies the package's MD5 digest.
	sha1Sum := sha1.Sum(leafCertificate.Raw) //nolint:gosec // G401: the test verifies the package's SHA-1 digest.
	sha256Sum := sha256.Sum256(leafCertificate.Raw)

	assert.Equal(t, hex.EncodeToString(md5Sum[:]), certificate.MD5())
	assert.Equal(t, hex.EncodeToString(sha1Sum[:]), certificate.SHA1())
	assert.Equal(t, hex.EncodeToString(sha256Sum[:]), certificate.SHA256())
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
