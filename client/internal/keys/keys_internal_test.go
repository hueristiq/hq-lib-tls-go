package keys

import (
	"encoding/hex"
	"testing"

	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

func TestExportKeyBlockVector(t *testing.T) {
	t.Parallel()

	master := make([]byte, 48)
	for i := range master {
		master[i] = byte(0x30)
	}

	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(0x30 + i)
	}

	serverRandom := make([]byte, 32)
	for i := range serverRandom {
		serverRandom[i] = byte(0x50 + i)
	}

	suite, known := hqgotlsciphers.ByID(0x0003)
	if !known {
		t.Fatal("suite 0x0003 not found")
	}

	block, err := DeriveKeyBlock(hqgotlsciphers.VersionTLS10, &suite, master, clientRandom, serverRandom)
	if err != nil {
		t.Fatal(err)
	}

	checks := map[string]struct {
		got  []byte
		want string
	}{
		"clientMAC": {block.ClientMAC, "b67175ed265cad59cb28e3bce4634307"},
		"serverMAC": {block.ServerMAC, "cdf6c54e85cd414c382962f835a2bddd"},
		"clientKey": {block.ClientKey, "74f07055ebc449f730e8122e5a24a4c5"},
		"serverKey": {block.ServerKey, "2c70e62f813f3df53b5f03a2f304e480"},
	}

	for name, check := range checks {
		if hex.EncodeToString(check.got) != check.want {
			t.Errorf("%s = %x, want %s", name, check.got, check.want)
		}
	}
}
