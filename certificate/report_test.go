package certificate_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	hqgotlscertificate "github.com/hueristiq/hq-lib-tls-go/certificate"
)

func testDER(t *testing.T) (der []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"Example"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		DNSNames:  []string{"example.com", "example.com", "*.example.com"},
	}

	der, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func TestCertificateHelpers(t *testing.T) {
	t.Parallel()

	parsed, err := hqgotlscertificate.Parse([][]byte{testDER(t)})
	if err != nil {
		t.Fatal(err)
	}

	leaf := parsed[0]

	if !leaf.Wildcard() {
		t.Error("Wildcard() = false, want true")
	}

	names := leaf.UniqueDNSNames()
	if len(names) != 2 {
		t.Fatalf("UniqueDNSNames() = %v, want 2 entries", names)
	}

	digests, err := leaf.Digests([]string{"md5", "sha1", "sha256"})
	if err != nil {
		t.Fatal(err)
	}

	for _, algorithm := range []string{"md5", "sha1", "sha256"} {
		if digests[algorithm] == "" {
			t.Fatalf("Digests() missing %s", algorithm)
		}
	}
}

func TestReportAnalyze(t *testing.T) {
	t.Parallel()

	report, err := hqgotlscertificate.Analyze([][]byte{testDER(t)}, "example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if report.SubjectCN != "example.com" {
		t.Fatalf("SubjectCN = %q", report.SubjectCN)
	}

	if report.Serial != "42" {
		t.Fatalf("Serial = %q", report.Serial)
	}

	if !report.Wildcard {
		t.Error("Wildcard = false, want true")
	}

	if report.Expired {
		t.Error("Expired = true, want false")
	}

	if report.Mismatched {
		t.Error("Mismatched = true, want false")
	}

	if len(report.SANs) != 2 {
		t.Fatalf("SANs = %v, want 2 entries", report.SANs)
	}
}
