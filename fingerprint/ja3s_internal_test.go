package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJA3S(t *testing.T) {
	t.Parallel()

	header := make([]byte, 35) // version(2) + random(32) + session ID length(1)

	copy(header, []byte{0x03, 0x03})

	cipherBytes := buildBody(appendUint16(nil, 0xc02f), []byte{0x00}) // cipher + compression

	extensions := extension(0x002b, []byte{0x00, 0x02, 0x03, 0x04})

	body := buildBody(header, cipherBytes, appendLength16(nil, len(extensions)), extensions)

	ja3s, err := JA3S(serverHelloMessage(body))

	require.NoError(t, err)
	assert.Equal(t, "771,49199,43", ja3s)
}

func TestJA3SSkipsGrease(t *testing.T) {
	t.Parallel()

	header := make([]byte, 35) // version(2) + random(32) + session ID length(1)

	copy(header, []byte{0x03, 0x03})

	cipherBytes := buildBody(appendUint16(nil, 0x1301), []byte{0x00}) // cipher + compression

	extensions := append([]byte{0x0a, 0x0a, 0x00, 0x00}, extension(0x002b, []byte{0x00, 0x02, 0x03, 0x04})...) // GREASE extension

	body := buildBody(header, cipherBytes, appendLength16(nil, len(extensions)), extensions)

	ja3s, err := JA3S(serverHelloMessage(body))

	require.NoError(t, err)
	assert.Equal(t, "771,4865,43", ja3s)
}

func TestJA3STruncated(t *testing.T) {
	t.Parallel()

	_, err := JA3S([]byte{0x02, 0x00, 0x00, 0x05, 0x03})

	assert.Error(t, err)
}

func TestJA3SErrorPaths(t *testing.T) {
	t.Parallel()

	version := []byte{0x03, 0x03}
	random := make([]byte, 32)

	tests := map[string]struct {
		body        []byte
		errContains string
	}{
		"version truncated": {
			body:        []byte{0x03},
			errContains: "truncated at the version field",
		},
		"session ID truncated": {
			body:        buildBody(version, random),
			errContains: "reading session ID",
		},
		"cipher suite truncated": {
			body:        buildBody(version, random, []byte{0x00}, []byte{0x13}),
			errContains: "truncated at the cipher suite field",
		},
		"extensions truncated": {
			body:        buildBody(version, random, []byte{0x00}, appendUint16(nil, 0x1301), []byte{0x00, 0x00}),
			errContains: "reading extensions",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := JA3S(serverHelloMessage(test.body))
			require.ErrorContains(t, err, test.errContains)
		})
	}
}

func FuzzJA3S(f *testing.F) {
	f.Add([]byte{0x02, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = JA3S(data)
	})
}
