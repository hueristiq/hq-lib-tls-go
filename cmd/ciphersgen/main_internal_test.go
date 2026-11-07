package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceSection(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ciphers.go")
	original := "package tls\n\n" + sectionBegin + "\nold\n" + sectionEnd + "\n"

	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := replaceSection(path, []byte("new\n")); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	want := "package tls\n\n" + sectionBegin + "\nnew\n" + sectionEnd + "\n"
	if string(got) != want {
		t.Fatalf("replaceSection() = %q; want %q", got, want)
	}
}

func TestReplaceSectionRequiresMarkers(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ciphers.go")
	if err := os.WriteFile(path, []byte("package tls\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := replaceSection(path, []byte("new\n")); err == nil {
		t.Fatal("expected a missing marker error")
	}
}
