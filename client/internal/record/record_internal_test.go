package record

import (
	"bytes"
	"testing"

	hqgotlsclientkeys "github.com/hueristiq/hq-lib-tls-go/client/internal/keys"

	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

func TestExportSuiteRecordRoundTrip(t *testing.T) {
	t.Parallel()

	ids := []uint16{
		0x0003, // RSA_EXPORT_RC4_40_MD5
		0x0006, // RSA_EXPORT_RC2_CBC_40_MD5
		0x0008, // RSA_EXPORT_DES40_CBC_SHA
		0x0014, // DHE_RSA_EXPORT_DES40_CBC_SHA
		0x0017, // DH_anon_EXPORT_RC4_40_MD5
		0x0019, // DH_anon_EXPORT_DES40_CBC_SHA
		0x0060, // RSA_EXPORT1024_RC4_56_MD5
		0x0061, // RSA_EXPORT1024_RC2_CBC_56_MD5
		0x0062, // RSA_EXPORT1024_DES_CBC_SHA
		0x0064, // RSA_EXPORT1024_RC4_56_SHA
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

	plaintext := []byte("export record plaintext")

	for _, id := range ids {
		suite, known := hqgotlsciphers.ByID(id)
		if !known {
			t.Fatalf("suite %#04x not found", id)
		}

		block, err := hqgotlsclientkeys.DeriveKeyBlock(hqgotlsciphers.VersionTLS10, &suite, master, clientRandom, serverRandom)
		if err != nil {
			t.Fatalf("%s: deriveKeyBlock: %v", suite.Name, err)
		}

		writer, err := NewProtection(&suite, hqgotlsciphers.VersionTLS10, block.ClientMAC, block.ClientKey, block.ClientIV, false)
		if err != nil {
			t.Fatalf("%s: writer protection: %v", suite.Name, err)
		}

		wire, err := writer.encrypt(TypeHandshake, hqgotlsciphers.VersionTLS10, plaintext)
		if err != nil {
			t.Fatalf("%s: encrypt: %v", suite.Name, err)
		}

		reader, err := NewProtection(&suite, hqgotlsciphers.VersionTLS10, block.ClientMAC, block.ClientKey, block.ClientIV, false)
		if err != nil {
			t.Fatalf("%s: reader protection: %v", suite.Name, err)
		}

		got, _, err := reader.decrypt(TypeHandshake, hqgotlsciphers.VersionTLS10, wire)
		if err != nil {
			t.Fatalf("%s: decrypt: %v", suite.Name, err)
		}

		if !bytes.Equal(got, plaintext) {
			t.Fatalf("%s: round trip got %x, want %x", suite.Name, got, plaintext)
		}
	}
}
