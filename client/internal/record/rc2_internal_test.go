package record

import (
	"encoding/hex"
	"testing"
)

func TestRC2Vectors(t *testing.T) {
	t.Parallel()

	vectors := []struct {
		key        string
		effective  int
		plaintext  string
		ciphertext string
	}{
		{"0000000000000000", 63, "0000000000000000", "ebb773f993278eff"},
		{"ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"},
		{"3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"},
		{"88", 64, "0000000000000000", "61a8a244adacccf0"},
		{"88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"},
		{"88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1"},
		{"88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6"},
		{"88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e", 129, "0000000000000000", "5b78d3a43dfff1f1"},
	}

	for _, vector := range vectors {
		key, err := hex.DecodeString(vector.key)
		if err != nil {
			t.Fatal(err)
		}

		plaintext, err := hex.DecodeString(vector.plaintext)
		if err != nil {
			t.Fatal(err)
		}

		expected, err := hex.DecodeString(vector.ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		block, err := newRC2Cipher(key, vector.effective)
		if err != nil {
			t.Fatalf("newRC2Cipher(%s, %d): %v", vector.key, vector.effective, err)
		}

		ciphertext := make([]byte, len(plaintext))
		block.Encrypt(ciphertext, plaintext)

		if hex.EncodeToString(ciphertext) != vector.ciphertext {
			t.Errorf("RC2 encrypt key=%s eff=%d: got %x, want %x", vector.key, vector.effective, ciphertext, expected)
		}

		decrypted := make([]byte, len(ciphertext))
		block.Decrypt(decrypted, ciphertext)

		if hex.EncodeToString(decrypted) != vector.plaintext {
			t.Errorf("RC2 decrypt key=%s eff=%d: got %x, want %x", vector.key, vector.effective, decrypted, plaintext)
		}
	}
}
