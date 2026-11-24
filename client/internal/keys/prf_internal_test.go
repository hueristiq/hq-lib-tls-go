package keys

import (
	"encoding/hex"
	"testing"
)

func testPRFInputs() (secret, seed, labelSeed []byte) {
	secret = make([]byte, 48)
	for i := range secret {
		secret[i] = byte(i)
	}

	seed = make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0x30 + i)
	}

	labelSeed = append([]byte("master secret"), seed...)

	return secret, seed, labelSeed
}

func TestPRF10Vector(t *testing.T) {
	t.Parallel()

	secret, _, labelSeed := testPRFInputs()

	got := prf10(secret, "master secret", labelSeed[len("master secret"):], 48)
	want := "58355564ac102fd3e89a7dd3bc07e7dbd2d224d18e94b80b734aa3336d3a3cde0fbaaba3c38861b1bb9a55b17ac2ffc6"

	if hex.EncodeToString(got) != want {
		t.Fatalf("prf10 = %x, want %s", got, want)
	}
}

func TestSSL3PRFVector(t *testing.T) {
	t.Parallel()

	secret, seed, _ := testPRFInputs()

	got := ssl3PRF(secret, seed, 48)
	want := "f1fbda815085ef2e166e71fb097949c81af8651e7deeb6e0041cba3b0da7caaac68428a55f8cc55d8ae12bbedaee9e62"

	if hex.EncodeToString(got) != want {
		t.Fatalf("ssl3PRF = %x, want %s", got, want)
	}
}

func TestExportPRF30Vector(t *testing.T) {
	t.Parallel()

	secret, seed, _ := testPRFInputs()

	got := exportPRF30(secret, seed, 16)
	want := "761f6d007f6e5c64c8d161a5ced4e0aa"

	if hex.EncodeToString(got) != want {
		t.Fatalf("exportPRF30 = %x, want %s", got, want)
	}
}
