package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func appendLength24(raw []byte, length int) []byte {
	if length < 0 || length > 0xFFFFFF {
		panic("fingerprint test: length does not fit in three bytes")
	}

	raw = append(raw, byte(length>>16), byte(length>>8), byte(length)) //nolint:gosec // G115: guarded by the bounds check above.

	return raw
}

func appendLength16(raw []byte, length int) []byte {
	if length < 0 || length > 0xFFFF {
		panic("fingerprint test: length does not fit in two bytes")
	}

	raw = append(raw, byte(length>>8), byte(length)) //nolint:gosec // G115: guarded by the bounds check above.

	return raw
}

func appendUint16(raw []byte, value uint16) []byte {
	raw = append(raw, byte(value>>8), byte(value&0xFF))

	return raw
}

func clientHelloMessage(body []byte) []byte {
	raw := make([]byte, 0, 4+len(body))
	raw = append(raw, 0x01)
	raw = appendLength24(raw, len(body))
	raw = append(raw, body...)

	return raw
}

func serverHelloMessage(body []byte) []byte {
	raw := make([]byte, 0, 4+len(body))
	raw = append(raw, 0x02)
	raw = appendLength24(raw, len(body))
	raw = append(raw, body...)

	return raw
}

func extension(extensionType uint16, data []byte) []byte {
	raw := make([]byte, 0, 4+len(data))
	raw = appendUint16(raw, extensionType)
	raw = appendLength16(raw, len(data))
	raw = append(raw, data...)

	return raw
}

func buildBody(parts ...[]byte) []byte {
	total := 0

	for _, part := range parts {
		total += len(part)
	}

	body := make([]byte, total)

	offset := 0

	for _, part := range parts {
		offset += copy(body[offset:], part)
	}

	return body
}

func TestJA3(t *testing.T) {
	t.Parallel()

	// ClientHello: TLS 1.2, ciphers [TLS_AES_128_GCM_SHA256, GREASE,
	// ECDHE-RSA-AES128-GCM], extensions [supported_groups, ec_point_formats,
	// GREASE], curves [x25519, secp256r1, GREASE], point formats [0].
	header := make([]byte, 35) // version(2) + random(32) + session ID length(1)

	copy(header, []byte{0x03, 0x03})

	cipherSuites := []uint16{0x1301, 0x0a0a, 0xc02f}

	cipherBytes := appendLength16(nil, len(cipherSuites)*2)

	for _, suite := range cipherSuites {
		cipherBytes = appendUint16(cipherBytes, suite)
	}

	extensions := append(
		append(extension(0x000a, []byte{0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x0a, 0x0a}), extension(0x000b, []byte{0x01, 0x00})...),
		0x0a, 0x0a, 0x00, 0x00,
	) // GREASE extension

	body := buildBody(header, cipherBytes, []byte{0x01, 0x00}, appendLength16(nil, len(extensions)), extensions)

	ja3, err := JA3(clientHelloMessage(body))

	require.NoError(t, err)
	assert.Equal(t, "771,4865-49199,10-11,29-23,0", ja3)
}

func TestJA3Truncated(t *testing.T) {
	t.Parallel()

	_, err := JA3([]byte{0x01, 0x00})

	require.Error(t, err)

	_, err = JA3(nil)

	require.Error(t, err)
}

func TestJA3WithoutExtensions(t *testing.T) {
	t.Parallel()

	header := make([]byte, 35) // version(2) + random(32) + session ID length(1)

	copy(header, []byte{0x03, 0x03})

	cipherBytes := buildBody(appendLength16(nil, 2), appendUint16(nil, 0x1301))

	body := buildBody(header, cipherBytes, []byte{0x01, 0x00}) // compression

	ja3, err := JA3(clientHelloMessage(body))

	require.NoError(t, err)
	assert.Equal(t, "771,4865,,,", ja3, "missing extensions yield empty segments")
}

func TestJA3ErrorPaths(t *testing.T) {
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
		"cipher suites truncated": {
			body:        buildBody(version, random, []byte{0x00}),
			errContains: "reading cipher suites",
		},
		"compression methods truncated": {
			body:        buildBody(version, random, []byte{0x00}, appendLength16(nil, 2), appendUint16(nil, 0x1301)),
			errContains: "reading compression methods",
		},
		"extensions truncated": {
			body:        buildBody(version, random, []byte{0x00}, appendLength16(nil, 2), appendUint16(nil, 0x1301), []byte{0x00, 0x00}),
			errContains: "reading extensions",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := JA3(clientHelloMessage(test.body))
			require.ErrorContains(t, err, test.errContains)
		})
	}
}

func TestJA3SkippedTruncatedExtension(t *testing.T) {
	t.Parallel()

	// The extension header declares five bytes of data but only two are
	// present, so the walk stops after recording the type.
	extensions := buildBody(appendUint16(nil, 0x000a), appendLength16(nil, 5), []byte{0x01, 0x02})

	types, curves, pointFormats := parseExtensions(extensions)

	assert.Equal(t, []uint16{0x000a}, types)
	assert.Empty(t, curves)
	assert.Empty(t, pointFormats)
}

func TestReadVariableTruncation(t *testing.T) {
	t.Parallel()

	_, _, err := readVariable([]byte{0x01}, 0, 2)
	require.ErrorContains(t, err, "truncated at a length field")

	_, _, err = readVariable([]byte{0x00, 0x05, 0x01}, 0, 2)
	require.ErrorContains(t, err, "truncated inside variable-length data")
}

func FuzzJA3(f *testing.F) {
	f.Add([]byte{0x01, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x2c})

	f.Fuzz(func(_ *testing.T, data []byte) {
		// Must never panic, only return an error on malformed input.
		_, _ = JA3(data)
	})
}
