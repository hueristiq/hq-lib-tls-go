package tls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

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
	// change-cipher-spec record); the parser's fixed offsets assume that
	// slack, so provide it.
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
	assert.Equal(t, "47", jarmCipherBytes("9999"), "unknown ciphers report the value beyond the last index")
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

func TestJARMInvalidHost(t *testing.T) {
	t.Parallel()

	client, err := New()
	require.NoError(t, err)

	_, err = client.JARM(context.Background(), "")
	require.ErrorContains(t, err, "host is empty")
}

func TestJARMTimeout(t *testing.T) {
	t.Parallel()

	address, stop := startHangingServer(t)
	defer stop()

	client, err := New(WithTimeout(100 * time.Millisecond))
	require.NoError(t, err)

	jarm, err := client.JARM(context.Background(), address)
	require.NoError(t, err)
	assert.Equal(t, jarmEmptyHash, jarm, "a timeout yields the all-zero hash")
}

func TestSendJARMProbeFailurePaths(t *testing.T) {
	t.Parallel()

	parameters := jarmProbes[0]

	tests := map[string]struct {
		conn   *fakeConn
		dialer *fakeDialer
		ctx    func(context.Context) context.Context
		err    bool
	}{
		"dial failure": {
			dialer: &fakeDialer{err: errors.New("dial failed")},
		},
		"deadline failure": {
			conn: &fakeConn{deadlineErr: errors.New("deadline failed")},
		},
		"write timeout": {
			conn: &fakeConn{writeErr: timeoutError{}},
			err:  true,
		},
		"write failure": {
			conn: &fakeConn{writeErr: errors.New("write failed")},
		},
		"read timeout": {
			conn: &fakeConn{readErr: timeoutError{}},
			err:  true,
		},
		"read failure": {
			conn: &fakeConn{readErr: errors.New("read failed")},
		},
		"context ended": {
			conn: &fakeConn{readData: syntheticServerHello(0x1301, nil)},
			ctx: func(ctx context.Context) context.Context {
				canceled, cancel := context.WithCancel(ctx)
				cancel()

				return canceled
			},
			err: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			if test.ctx != nil {
				ctx = test.ctx(ctx)
			}

			dialer := test.dialer
			if dialer == nil {
				dialer = &fakeDialer{conn: test.conn}
			}

			client := newTestClient(t, dialer)

			hello, err := client.sendJARMProbe(ctx, "example.com", "example.com:443", &parameters)

			if test.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.Empty(t, hello.cipher)
		})
	}
}

func TestJARMMungEvenLength(t *testing.T) {
	t.Parallel()

	items := []uint16{1, 2, 3, 4}

	assert.Equal(t, []uint16{3, 4}, jarmMung(items, "BOTTOM_HALF"))
	assert.Equal(t, []uint16{2, 1}, jarmMung(items, "TOP_HALF"))
	assert.Equal(t, []uint16{3, 2, 4, 1}, jarmMung(items, "MIDDLE_OUT"))
}

func jarmEdgeData(length int) (data []byte) {
	data = make([]byte, length)
	data[0] = 22
	data[3] = 0xFF
	data[4] = 0xFF
	data[5] = 2
	data[43] = 0

	return data
}

func TestParseJARMServerHelloEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("counter beyond buffer", func(t *testing.T) {
		t.Parallel()

		data := jarmEdgeData(46)
		data[43] = 200

		assert.Empty(t, parseJARMServerHello(data).extensions)
	})

	t.Run("extension length sentinel", func(t *testing.T) {
		t.Parallel()

		data := jarmEdgeData(49)
		data[47] = 11

		hello := parseJARMServerHello(data)
		assert.Equal(t, "0000", hello.version)
		assert.Empty(t, hello.extensions)
	})

	t.Run("extension value sentinel", func(t *testing.T) {
		t.Parallel()

		data := jarmEdgeData(53)
		data[47] = 0
		data[50], data[51], data[52] = 0x0e, 0xac, 0x0b

		assert.Empty(t, parseJARMServerHello(data).extensions)
	})

	t.Run("record value sentinel", func(t *testing.T) {
		t.Parallel()

		data := jarmEdgeData(85)
		data[47] = 0
		data[82], data[83], data[84] = 0x0f, 0xf0, 0x0b

		assert.Empty(t, parseJARMServerHello(data).extensions)
	})

	t.Run("server hello length below counter", func(t *testing.T) {
		t.Parallel()

		data := jarmEdgeData(49)
		data[3], data[4] = 0x00, 0x0a

		hello := parseJARMServerHello(data)
		assert.Equal(t, "0000", hello.version)
		assert.Empty(t, hello.extensions)
	})

	t.Run("extension header beyond buffer", func(t *testing.T) {
		t.Parallel()

		data := jarmEdgeData(50)
		data[47], data[48] = 0, 10

		assert.Empty(t, parseJARMServerHello(data).extensions)
	})

	t.Run("extension payload beyond buffer", func(t *testing.T) {
		t.Parallel()

		data := jarmEdgeData(60)
		data[47], data[48] = 0, 10
		data[51], data[52] = 0, 100

		assert.Empty(t, parseJARMServerHello(data).extensions)
	})
}

func TestRandomGreaseFailure(t *testing.T) {
	t.Parallel()

	assert.Equal(t, uint16(0x0a0a), randomGrease(failingReader{}))
}

func TestRandomBytesPanicsOnEntropyFailure(t *testing.T) {
	t.Parallel()

	require.Panics(t, func() {
		randomBytes(failingReader{}, 16)
	})
}

func TestAppendLengthPanics(t *testing.T) {
	t.Parallel()

	require.Panics(t, func() { appendLength8(nil, 0x100) })
	require.Panics(t, func() { appendLength16(nil, 0x10000) })
	require.Panics(t, func() { appendLength24(nil, 0x1000000) })
}

func TestJARM(t *testing.T) {
	t.Parallel()

	address, stop := startTLSServer(t)

	defer stop()

	client, err := New(WithTimeout(5 * time.Second))

	require.NoError(t, err)

	jarm, err := client.JARM(context.Background(), address)

	require.NoError(t, err)
	assert.Len(t, jarm, 62)
	assert.NotEqual(t, jarmEmptyHash, jarm, "a responsive server yields a real fingerprint")
}

func TestJARMUnreachableHost(t *testing.T) {
	t.Parallel()

	client, err := New(WithTimeout(time.Second))

	require.NoError(t, err)

	jarm, err := client.JARM(context.Background(), "127.0.0.1:1")

	require.NoError(t, err)
	assert.Equal(t, jarmEmptyHash, jarm)
}

func startHangingServer(t *testing.T) (address string, stop func()) {
	t.Helper()

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})

	var once sync.Once

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()

		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}

			go func() {
				<-done

				_ = conn.Close()
			}()
		}
	}()

	stop = func() {
		once.Do(func() {
			_ = listener.Close()

			close(done)
			wg.Wait()
		})
	}

	return listener.Addr().String(), stop
}
