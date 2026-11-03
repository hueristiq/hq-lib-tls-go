package tls_test

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	hqgotls "github.com/hueristiq/hq-lib-tls-go"
)

// newLocalTLS starts a TLS test server and returns its host:port.
func newLocalTLS(t *testing.T) string {
	t.Helper()

	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)

	return strings.TrimPrefix(server.URL, "https://")
}

func TestEnumerateVersions(t *testing.T) {
	t.Parallel()

	host := newLocalTLS(t)

	client, err := hqgotls.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	versions, err := client.EnumerateVersions(context.Background(), host)
	if err != nil {
		t.Fatalf("EnumerateVersions() error = %v", err)
	}

	if len(versions) == 0 {
		t.Fatal("EnumerateVersions() returned no versions against a TLS test server")
	}

	if !slices.IsSorted(versions) {
		t.Errorf("EnumerateVersions() = %v; want ascending order", versions)
	}

	// The standard library test server supports at least TLS 1.2.
	if !slices.Contains(versions, tls.VersionTLS12) && !slices.Contains(versions, tls.VersionTLS13) {
		t.Errorf("EnumerateVersions() = %v; want TLS 1.2 or 1.3", versions)
	}
}

func TestEnumerateVersionsCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client, err := hqgotls.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err = client.EnumerateVersions(ctx, "127.0.0.1:1"); err == nil {
		t.Error("EnumerateVersions() with canceled context: expected error")
	}
}

func TestEnumerateCipherSuites(t *testing.T) {
	t.Parallel()

	host := newLocalTLS(t)

	client, err := hqgotls.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// concurrency 0 exercises the clamp to one worker.
	suites, err := client.EnumerateCipherSuites(context.Background(), host, 0)
	if err != nil {
		t.Fatalf("EnumerateCipherSuites() error = %v", err)
	}

	if len(suites) == 0 {
		t.Fatal("EnumerateCipherSuites() returned no suites against a TLS test server")
	}

	if !slices.IsSorted(suites) {
		t.Errorf("EnumerateCipherSuites() = %v; want ascending order", suites)
	}
}

func TestEnumerateCipherSuitesCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client, err := hqgotls.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err = client.EnumerateCipherSuites(ctx, "127.0.0.1:1", 4); err == nil {
		t.Error("EnumerateCipherSuites() with canceled context: expected error")
	}
}
