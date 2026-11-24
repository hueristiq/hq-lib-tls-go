package tls_test

import (
	"context"
	"testing"
	"time"

	hqgotls "github.com/hueristiq/hq-lib-tls-go"
)

func TestClientJARM(t *testing.T) {
	t.Parallel()

	host := newLocalTLS(t)

	client, err := hqgotls.New(hqgotls.WithTimeout(5 * time.Second))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	jarm, err := client.JARM(context.Background(), host)
	if err != nil {
		t.Fatalf("JARM() error = %v", err)
	}

	if len(jarm) != 62 {
		t.Fatalf("JARM() length = %d, want 62", len(jarm))
	}
}
