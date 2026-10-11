package fingerprint

import (
	"crypto/md5" //nolint:gosec // G501: the digest under test is defined as an MD5 hash.
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// appendLength24 appends a 24-bit length with explicit bounds, mirroring
// the production encoders.
func appendLength24(raw []byte, length int) []byte {
	if length < 0 || length > 0xFFFFFF {
		panic("fingerprint test: length does not fit in three bytes")
	}

	raw = append(raw, byte(length>>16), byte(length>>8), byte(length)) //nolint:gosec // G115: guarded by the bounds check above.

	return raw
}

// appendLength16 appends a 16-bit length with explicit bounds.
func appendLength16(raw []byte, length int) []byte {
	if length < 0 || length > 0xFFFF {
		panic("fingerprint test: length does not fit in two bytes")
	}

	raw = append(raw, byte(length>>8), byte(length)) //nolint:gosec // G115: guarded by the bounds check above.

	return raw
}

// appendUint16 appends a uint16 in big-endian order.
func appendUint16(raw []byte, value uint16) []byte {
	raw = append(raw, byte(value>>8), byte(value&0xFF))

	return raw
}

// clientHelloMessage builds a ClientHello handshake message.
func clientHelloMessage(body []byte) []byte {
	raw := make([]byte, 0, 4+len(body))
	raw = append(raw, 0x01)
	raw = appendLength24(raw, len(body))
	raw = append(raw, body...)

	return raw
}

// serverHelloMessage builds a ServerHello handshake message.
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

// buildBody concatenates parts into a single buffer with copy, keeping
// the synthetic fixtures free of append chains.
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

func TestDigest(t *testing.T) {
	t.Parallel()

	const segment = "771,49199,43"

	sum := md5.Sum([]byte(segment)) //nolint:gosec // G401: the digest under test is defined as an MD5 hash.

	assert.Equal(t, hex.EncodeToString(sum[:]), Digest(segment))
}
