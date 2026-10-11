package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syntheticServerHello builds a TLS record containing a ServerHello with
// the given cipher and extension pairs, mirroring what a server would send
// as its first flight.
func syntheticServerHello(cipher uint16, extensions [][]byte) []byte {
	body := make([]byte, 0, 64)
	body = appendUint16(body, 0x0303)
	body = append(append(body, make([]byte, 32)...), 0x00) // random + empty session ID
	body = appendUint16(body, cipher)
	body = append(body, 0x00) // compression: null

	var extBlock []byte

	for _, extension := range extensions {
		extBlock = append(extBlock, extension...)
	}

	body = appendLength16(body, len(extBlock))
	body = append(body, extBlock...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x02)
	handshake = appendLength24(handshake, len(body))
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16, 0x03, 0x03)
	record = appendLength16(record, len(handshake))
	record = append(record, handshake...)

	return record
}

func extensionBytes(extensionType uint16, data []byte) []byte {
	extension := make([]byte, 0, 4+len(data))
	extension = appendUint16(extension, extensionType)
	extension = appendLength16(extension, len(data))
	extension = append(extension, data...)

	return extension
}

func TestParseJARMServerHello(t *testing.T) {
	t.Parallel()

	record := syntheticServerHello(0x1301, [][]byte{
		extensionBytes(0x002b, []byte{0x00, 0x02, 0x03, 0x04}),                              // supported_versions
		extensionBytes(0x0033, append([]byte{0x00, 0x1d, 0x00, 0x20}, make([]byte, 32)...)), // key_share
	})

	hello := parseJARMServerHello(record)

	assert.Equal(t, "1301", hello.cipher)
	assert.Equal(t, "0303", hello.version)
	assert.Equal(t, "002b-0033", hello.extensions)
	assert.Empty(t, hello.alpn)
}

func TestParseJARMServerHelloALPN(t *testing.T) {
	t.Parallel()

	// ALPN extension value: list length (2) + protocol length (1) + name.
	record := syntheticServerHello(0x1301, [][]byte{
		extensionBytes(0x0010, []byte{0x00, 0x04, 0x03, 'f', 'o', 'o'}),
	})

	// A real server flight carries bytes beyond the ServerHello (the
	// change-cipher-spec record); the reference parser's offsets assume
	// that slack, so provide it.
	flight := append(append([]byte{}, record...), 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)

	hello := parseJARMServerHello(flight)

	assert.Equal(t, "foo", hello.alpn)
}

func TestParseJARMServerHelloRejectsNoise(t *testing.T) {
	t.Parallel()

	assert.Empty(t, parseJARMServerHello(nil).cipher)
	assert.Empty(t, parseJARMServerHello([]byte("not tls")).cipher)

	alert := []byte{21, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}

	assert.Empty(t, parseJARMServerHello(alert).cipher)
}

func TestJARMHashDeterministic(t *testing.T) {
	t.Parallel()

	hello := jarmHello{
		cipher:     "1301",
		version:    "0303",
		alpn:       "",
		extensions: "002b-0033",
	}

	hellos := make([]jarmHello, len(jarmProbes))

	for i := range hellos {
		hellos[i] = hello
	}

	hash := jarmHash(hellos)

	assert.Len(t, hash, 62)
	assert.NotEqual(t, jarmEmptyHash, hash)

	expectedFuzzy := strings.Repeat("20d", len(jarmProbes))

	alpnAndExtensions := strings.Repeat("002b-0033", len(jarmProbes))

	sum := sha256.Sum256([]byte(alpnAndExtensions))

	expected := expectedFuzzy + hex.EncodeToString(sum[:])[:32]

	assert.Equal(t, expected, hash)
	assert.Equal(t, hash, jarmHash(hellos), "the hash is deterministic")
}

func TestJARMHashEmpty(t *testing.T) {
	t.Parallel()

	assert.Equal(t, jarmEmptyHash, jarmHash(make([]jarmHello, len(jarmProbes))))
}

func TestJARMCipherBytes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "00", jarmCipherBytes(""))
	assert.Equal(t, "01", jarmCipherBytes("0016"))
	assert.Equal(t, "20", jarmCipherBytes("1301"))
	assert.Equal(t, "47", jarmCipherBytes("9999"), "unknown ciphers exhaust the list, as in the reference")
}

func TestJARMVersionByte(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "0", jarmVersionByte(""))
	assert.Equal(t, "a", jarmVersionByte("0300"))
	assert.Equal(t, "b", jarmVersionByte("0301"))
	assert.Equal(t, "c", jarmVersionByte("0302"))
	assert.Equal(t, "d", jarmVersionByte("0303"))
	assert.Equal(t, "e", jarmVersionByte("0304"))
	assert.Equal(t, "0", jarmVersionByte("03ff"), "out-of-range minors fall back to zero")
}

func TestBuildJARMClientHello(t *testing.T) {
	t.Parallel()

	parameters := jarmProbes[0]

	packet := buildJARMClientHello("example.com", &parameters)

	require.NotEmpty(t, packet)
	assert.Equal(t, byte(0x16), packet[0], "the first byte is the handshake record type")
	assert.Contains(t, string(packet), "example.com", "the SNI is embedded")

	// The record length must match the payload length.
	length := int(packet[3])<<8 | int(packet[4])

	assert.Equal(t, len(packet)-5, length)
}

func TestJARMProbeParametersRoundTrip(t *testing.T) {
	t.Parallel()

	for _, parameters := range jarmProbes {
		packet := buildJARMClientHello("example.com", &parameters)

		assert.NotEmpty(t, packet, "every probe combination builds a packet")
		assert.Len(t, jarmProbes, 10, "the probe count is part of the specification")
	}
}

func TestJARMMung(t *testing.T) {
	t.Parallel()

	items := []uint16{1, 2, 3, 4, 5}

	assert.Equal(t, []uint16{1, 2, 3, 4, 5}, jarmMung(items, "FORWARD"))
	assert.Equal(t, []uint16{5, 4, 3, 2, 1}, jarmMung(items, "REVERSE"))
	assert.Equal(t, []uint16{4, 5}, jarmMung(items, "BOTTOM_HALF"), "odd count drops the middle from the bottom half")
	assert.Equal(t, []uint16{3, 2, 1}, jarmMung(items, "TOP_HALF"), "odd count keeps the middle at the top")
	assert.Equal(t, []uint16{3, 4, 2, 5, 1}, jarmMung(items, "MIDDLE_OUT"))
}
