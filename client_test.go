package tls_test

import (
	"context"
	"crypto/tls"
	"testing"

	hqgotls "github.com/hueristiq/hq-lib-tls-go"
)

func TestNewDefaults(t *testing.T) {
	t.Parallel()

	client, err := hqgotls.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if client == nil {
		t.Fatal("New() returned nil")
	}
}

func TestInspectEmptyHost(t *testing.T) {
	t.Parallel()

	client, err := hqgotls.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err = client.Inspect(context.Background(), ""); err == nil {
		t.Error("Inspect(\"\") : expected error for an empty host")
	}
}

func TestInspectLocalServer(t *testing.T) {
	t.Parallel()

	host := newLocalTLS(t)

	client, err := hqgotls.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := client.Inspect(context.Background(), host)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}

	if result.TLSVersion != tls.VersionTLS12 && result.TLSVersion != tls.VersionTLS13 {
		t.Errorf("Inspect() TLSVersion = %#04x; want TLS 1.2 or 1.3", result.TLSVersion)
	}

	if len(result.Certificates) == 0 {
		t.Error("Inspect() returned no peer certificates")
	}
}
