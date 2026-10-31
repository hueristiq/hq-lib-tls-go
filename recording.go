package tls

import (
	"errors"
	"net"
	"sync"
)

// errPreHandshakeAborted is returned by a recordingConn read or write once
// the server's Certificate message has been fully captured in pre-handshake
// mode. It is an expected condition, not a failure.
var errPreHandshakeAborted = errors.New("client.Inspect: connection closed after server certificate capture (pre-handshake)")

const (
	// recordHeaderLength is the length of a TLS record header.
	recordHeaderLength = 5
	// handshakeHeaderLength is the length of a TLS handshake message header.
	handshakeHeaderLength = 4
	// handshakeTypeClientHello identifies ClientHello handshake messages.
	handshakeTypeClientHello = 1
	// handshakeTypeServerHello identifies ServerHello handshake messages.
	handshakeTypeServerHello = 2
	// handshakeTypeCertificate identifies Certificate handshake messages.
	handshakeTypeCertificate = 11
)

// recordingConn tees the bytes of a TLS connection so the client can
// capture the ClientHello it sent and the ServerHello it received. In
// pre-handshake mode it also terminates the connection once the server's
// Certificate message has been fully delivered, so the handshake goroutine
// aborts after the data it needs has been parsed into the handshake log.
//
// Fields:
//   - Conn (net.Conn): the wrapped connection.
//   - earlyClose (bool): whether to abort after the certificate capture.
//   - mu (sync.Mutex): guards the byte buffers and the abort flag.
//   - readBuffer ([]byte): every byte read from the wrapped connection.
//   - writeBuffer ([]byte): every byte written to the wrapped connection.
//   - aborted (bool): set once the certificate has been captured.
type recordingConn struct {
	net.Conn

	earlyClose  bool
	mu          sync.Mutex
	readBuffer  []byte
	writeBuffer []byte
	aborted     bool
}

// newRecordingConn wraps conn in a recordingConn.
//
// Parameters:
//   - conn (net.Conn): the connection to wrap.
//   - earlyClose (bool): whether to abort the connection after the server's
//     certificate message has been captured.
//
// Returns:
//   - recording (*recordingConn): the wrapped connection.
func newRecordingConn(conn net.Conn, earlyClose bool) (recording *recordingConn) {
	recording = &recordingConn{
		Conn:       conn,
		earlyClose: earlyClose,
	}

	return recording
}

// Read reads from the wrapped connection, teeing the bytes into the read
// buffer. In early-close mode, once the server's Certificate message has
// been fully captured, subsequent calls fail with [errPreHandshakeAborted].
//
// Parameters:
//   - b ([]byte): the destination buffer.
//
// Returns:
//   - n (int): the number of bytes read.
//   - err (error): the read error, if any.
func (c *recordingConn) Read(b []byte) (n int, err error) {
	if c.isAborted() {
		return 0, errPreHandshakeAborted
	}

	n, err = c.Conn.Read(b)

	if n > 0 {
		c.mu.Lock()

		c.readBuffer = append(c.readBuffer, b[:n]...)

		if c.earlyClose && !c.aborted && certificateMessageComplete(c.readBuffer) {
			c.aborted = true
		}

		c.mu.Unlock()
	}

	return n, err
}

// Write writes to the wrapped connection, teeing the bytes into the write
// buffer. In early-close mode, once the server's Certificate message has
// been fully captured, subsequent calls fail with
// [errPreHandshakeAborted], so the client never sends its key exchange.
//
// Parameters:
//   - b ([]byte): the bytes to write.
//
// Returns:
//   - n (int): the number of bytes written.
//   - err (error): the write error, if any.
func (c *recordingConn) Write(b []byte) (n int, err error) {
	if c.isAborted() {
		return 0, errPreHandshakeAborted
	}

	n, err = c.Conn.Write(b)

	if n > 0 {
		c.mu.Lock()
		c.writeBuffer = append(c.writeBuffer, b[:n]...)
		c.mu.Unlock()
	}

	return n, err
}

// isAborted reports whether the early-close abort has been triggered.
//
// Returns:
//   - aborted (bool): whether the connection has been aborted.
func (c *recordingConn) isAborted() (aborted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.aborted
}

// clientHello returns the raw ClientHello handshake message the client
// sent (header included), or nil when none has been captured.
//
// Returns:
//   - raw ([]byte): the ClientHello message.
func (c *recordingConn) clientHello() (raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return firstHandshakeMessage(c.writeBuffer, handshakeTypeClientHello)
}

// serverHello returns the raw ServerHello handshake message the server
// sent (header included), or nil when none has been captured.
//
// Returns:
//   - raw ([]byte): the ServerHello message.
func (c *recordingConn) serverHello() (raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return firstHandshakeMessage(c.readBuffer, handshakeTypeServerHello)
}

// certificateMessageComplete reports whether buffer contains a complete
// Certificate handshake message. It walks TLS records from the start of the
// buffer and handshake messages within each record; a Certificate message
// whose full body is present completes the capture.
//
// Parameters:
//   - buffer ([]byte): the captured bytes so far.
//
// Returns:
//   - complete (bool): whether a Certificate message has been fully captured.
func certificateMessageComplete(buffer []byte) (complete bool) {
	for offset := 0; offset+recordHeaderLength <= len(buffer); {
		recordLength := int(buffer[offset+3])<<8 | int(buffer[offset+4])

		end := offset + recordHeaderLength + recordLength

		if end > len(buffer) {
			return false
		}

		payload := buffer[offset+recordHeaderLength : end]

		for messageOffset := 0; messageOffset+handshakeHeaderLength <= len(payload); {
			messageLength := int(payload[messageOffset+1])<<16 | int(payload[messageOffset+2])<<8 | int(payload[messageOffset+3])
			messageEnd := messageOffset + handshakeHeaderLength + messageLength

			if messageEnd > len(payload) {
				break
			}

			if payload[messageOffset] == handshakeTypeCertificate {
				return true
			}

			messageOffset = messageEnd
		}

		offset = end
	}

	return false
}

// firstHandshakeMessage extracts the first handshake message of the given
// type from the captured buffer: it walks the first TLS record and returns
// the message with its four-byte handshake header.
//
// Parameters:
//   - buffer ([]byte): the captured bytes.
//   - messageType (byte): the handshake message type to look for.
//
// Returns:
//   - raw ([]byte): the handshake message, or nil when absent or incomplete.
func firstHandshakeMessage(buffer []byte, messageType byte) (raw []byte) {
	if len(buffer) < recordHeaderLength+handshakeHeaderLength {
		return nil
	}

	recordLength := int(buffer[3])<<8 | int(buffer[4])

	end := recordHeaderLength + recordLength

	if end > len(buffer) {
		return nil
	}

	payload := buffer[recordHeaderLength:end]

	if payload[0] != messageType {
		return nil
	}

	messageLength := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	messageEnd := handshakeHeaderLength + messageLength

	if messageEnd > len(payload) {
		return nil
	}

	raw = make([]byte, messageEnd)

	copy(raw, payload[:messageEnd])

	return raw
}
