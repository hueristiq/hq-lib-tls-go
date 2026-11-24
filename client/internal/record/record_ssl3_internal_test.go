package record

import (
	"bytes"
	"testing"

	hqgotlsclientkeys "github.com/hueristiq/hq-lib-tls-go/client/internal/keys"

	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

func TestSSL3RecordRoundTrip(t *testing.T) {
	t.Parallel()

	suite, known := hqgotlsciphers.ByID(0x000A) // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	if !known {
		t.Fatal("suite 0x000a not found")
	}

	master := make([]byte, 48)
	for i := range master {
		master[i] = byte(i)
	}

	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(0x30 + i)
	}

	serverRandom := make([]byte, 32)
	for i := range serverRandom {
		serverRandom[i] = byte(0x50 + i)
	}

	block, err := hqgotlsclientkeys.DeriveKeyBlock(hqgotlsciphers.VersionSSL30, &suite, master, clientRandom, serverRandom)
	if err != nil {
		t.Fatal(err)
	}

	writer, err := NewProtection(&suite, hqgotlsciphers.VersionSSL30, block.ClientMAC, block.ClientKey, block.ClientIV, false)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("ssl3 record plaintext")

	wire, err := writer.encrypt(TypeHandshake, hqgotlsciphers.VersionSSL30, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	reader, err := NewProtection(&suite, hqgotlsciphers.VersionSSL30, block.ClientMAC, block.ClientKey, block.ClientIV, false)
	if err != nil {
		t.Fatal(err)
	}

	got, _, err := reader.decrypt(TypeHandshake, hqgotlsciphers.VersionSSL30, wire)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("SSL 3.0 round trip got %x, want %x", got, plaintext)
	}
}
