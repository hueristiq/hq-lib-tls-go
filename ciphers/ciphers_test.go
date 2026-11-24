package ciphers_test

import (
	"slices"
	"testing"

	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

func TestByName(t *testing.T) {
	t.Parallel()

	names := []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"ECDHE-RSA-AES128-GCM-SHA256",
		"0xc02f",
		"c02f",
	}

	for _, name := range names {
		suite, known := hqgotlsciphers.ByName(name)
		if !known {
			t.Fatalf("ByName(%q) not found", name)
		}

		if suite.ID != 0xC02F {
			t.Fatalf("ByName(%q) = %#04x, want 0xc02f", name, suite.ID)
		}
	}
}

func TestParseList(t *testing.T) {
	t.Parallel()

	ids, err := hqgotlsciphers.ParseList("secure,0x0003,EXP-RC4-MD5")
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Contains(ids, uint16(0x0003)) {
		t.Fatal("ParseList did not include the explicit export suite")
	}

	if !slices.Contains(ids, uint16(0xC02F)) {
		t.Fatal("ParseList did not include secure suites")
	}

	if len(ids) != len(slices.Compact(slices.Clone(ids))) {
		t.Fatal("ParseList returned duplicates")
	}
}

func TestParseSecurity(t *testing.T) {
	t.Parallel()

	tests := map[string]hqgotlsciphers.Security{
		"all":         hqgotlsciphers.SecurityInsecure,
		"insecure":    hqgotlsciphers.SecurityInsecure,
		"weak":        hqgotlsciphers.SecurityWeak,
		"secure":      hqgotlsciphers.SecuritySecure,
		"recommended": hqgotlsciphers.SecurityRecommended,
	}

	for name, want := range tests {
		got, err := hqgotlsciphers.ParseSecurity(name)
		if err != nil {
			t.Fatalf("ParseSecurity(%q): %v", name, err)
		}

		if got != want {
			t.Fatalf("ParseSecurity(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestExportSuites(t *testing.T) {
	t.Parallel()

	exportSuites := hqgotlsciphers.Export()
	if len(exportSuites) == 0 {
		t.Fatal("Export() returned no suites")
	}

	for _, suite := range exportSuites {
		if !suite.Export {
			t.Fatalf("%s is not marked export", suite.Name)
		}

		if !suite.Implemented {
			t.Fatalf("%s is not marked implemented", suite.Name)
		}
	}
}

func TestSecurityOf(t *testing.T) {
	t.Parallel()

	security, known := hqgotlsciphers.SecurityOf(0xC02F)
	if !known {
		t.Fatal("SecurityOf(0xc02f) not known")
	}

	if security != hqgotlsciphers.SecurityRecommended {
		t.Fatalf("SecurityOf(0xc02f) = %v, want recommended", security)
	}
}
