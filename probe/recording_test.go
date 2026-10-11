package probe

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handshakeRecord wraps a handshake message into a TLS record.
func handshakeRecord(messageType byte, body []byte) []byte {
	handshake := make([]byte, 0, handshakeHeaderLength+len(body))
	handshake = append(handshake, messageType)
	handshake = appendLength24(handshake, len(body))
	handshake = append(handshake, body...)

	record := make([]byte, 0, recordHeaderLength+len(handshake))
	record = append(record, 0x16, 0x03, 0x03)
	record = appendLength16(record, len(handshake))
	record = append(record, handshake...)

	return record
}

func TestFirstHandshakeMessage(t *testing.T) {
	t.Parallel()

	body := []byte{0x03, 0x03, 0x01, 0x02, 0x03}

	buffer := handshakeRecord(handshakeTypeServerHello, body)

	hello := firstHandshakeMessage(buffer, handshakeTypeServerHello)

	require.NotNil(t, hello)
	assert.Equal(t, byte(handshakeTypeServerHello), hello[0])
	assert.Equal(t, body, hello[4:])

	assert.Nil(t, firstHandshakeMessage(buffer, handshakeTypeClientHello), "wrong type yields nothing")
	assert.Nil(t, firstHandshakeMessage(buffer[:10], handshakeTypeServerHello), "truncated record yields nothing")
	assert.Nil(t, firstHandshakeMessage(nil, handshakeTypeServerHello))
}

func TestCertificateMessageComplete(t *testing.T) {
	t.Parallel()

	record := handshakeRecord(handshakeTypeCertificate, []byte{0x00, 0x01, 0x02})

	assert.True(t, certificateMessageComplete(record), "a complete certificate message ends the capture")
	assert.False(t, certificateMessageComplete(record[:len(record)-2]), "a truncated certificate message does not")
	assert.False(t, certificateMessageComplete(nil))

	serverHello := handshakeRecord(handshakeTypeServerHello, []byte{0x03, 0x03})

	assert.False(t, certificateMessageComplete(serverHello), "other handshake messages do not trigger the capture")

	combined := append(append([]byte{}, serverHello...), record...)

	assert.True(t, certificateMessageComplete(combined), "the certificate after a ServerHello is found across records")
}

func TestRecordingConnEarlyClose(t *testing.T) {
	t.Parallel()

	clientSide, serverSide := net.Pipe()

	defer func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
	}()

	recording := newRecordingConn(clientSide, true)

	record := handshakeRecord(handshakeTypeCertificate, []byte{0x00, 0x01})

	go func() {
		_, _ = serverSide.Write(record)
	}()

	buffer := make([]byte, len(record))

	n, err := recording.Read(buffer)

	require.NoError(t, err)
	assert.Equal(t, len(record), n)

	_, err = recording.Write([]byte{0x01})

	require.ErrorIs(t, err, errPreHandshakeAborted, "writes abort once the certificate is captured")

	_, err = recording.Read(buffer)

	require.ErrorIs(t, err, errPreHandshakeAborted, "reads abort once the certificate is captured")
}

func TestRecordingConnWithoutEarlyClose(t *testing.T) {
	t.Parallel()

	clientSide, serverSide := net.Pipe()

	defer func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
	}()

	recording := newRecordingConn(clientSide, false)

	record := handshakeRecord(handshakeTypeCertificate, []byte{0x00, 0x01})

	go func() {
		_, _ = serverSide.Write(record)
	}()

	buffer := make([]byte, len(record))

	_, err := recording.Read(buffer)

	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		buffer := make([]byte, 1)

		_, _ = serverSide.Read(buffer)

		close(done)
	}()

	n, err := recording.Write([]byte{0x01})

	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Nil(t, recording.clientHello())
	assert.NotErrorIs(t, err, errPreHandshakeAborted)

	<-done
}
