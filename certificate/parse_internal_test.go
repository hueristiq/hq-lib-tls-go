package certificate

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"

	zcryptox509 "github.com/zmap/zcrypto/x509"
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

func TestPEMBlock(t *testing.T) {
	t.Parallel()

	_, _, leafCertificate := testCA(t, []string{"example.com"})

	leaf, err := Parse([][]byte{leafCertificate.Raw})
	require.NoError(t, err)

	pemBytes := leaf[0].PEMBlock()

	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Equal(t, leafCertificate.Raw, block.Bytes)
}

func TestParseOneWithFallbackToStdlib(t *testing.T) {
	t.Parallel()

	caCertificate, _, leafCertificate := testCA(t, []string{"example.com"})

	zcryptoFailure := func([]byte) (certificate *zcryptox509.Certificate, err error) {
		return nil, errors.New("zcrypto rejected the certificate")
	}

	certificate, err := parseOneWith(leafCertificate.Raw, zcryptoFailure, x509.ParseCertificate)
	require.NoError(t, err)
	assert.Equal(t, leafCertificate.Raw, certificate.Raw)
	assert.Equal(t, []string{"example.com"}, certificate.DNSNames)

	chain, err := Parse([][]byte{leafCertificate.Raw, caCertificate.Raw})
	require.NoError(t, err)
	assert.Equal(t, leafCertificate.Raw, chain[0].Raw)
}

func TestParseOneWithBothParsersFail(t *testing.T) {
	t.Parallel()

	_, err := parseOneWith([]byte("not a certificate"), func([]byte) (*zcryptox509.Certificate, error) {
		return nil, errors.New("zcrypto rejected the certificate")
	}, func([]byte) (*x509.Certificate, error) {
		return nil, errors.New("stdlib rejected the certificate")
	})
	require.ErrorContains(t, err, "neither parser accepted the certificate")
}

func TestParseOneWithEmptyInput(t *testing.T) {
	t.Parallel()

	_, err := parseOneWith(nil, zcryptox509.ParseCertificate, x509.ParseCertificate)
	require.ErrorContains(t, err, "certificate is empty")
}
