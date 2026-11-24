package client

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/hueristiq/hq-lib-tls-go/client/internal/record"
)

// Direction reports whether a handshake message was sent or received.
type Direction uint8

const (
	// Sent marks a message written by the client.
	Sent Direction = iota
	// Received marks a message read from the server.
	Received
)

// String returns "sent" or "received".
func (d Direction) String() (text string) {
	switch d {
	case Sent:
		text = "sent"
	case Received:
		text = "received"
	default:
		text = "unknown"
	}

	return text
}

// HandshakeEvent is one decrypted protocol message observed during the
// handshake. Because the engine owns the key schedule, Body is plaintext for
// every version, including messages carried in TLS 1.3 encrypted records.
type HandshakeEvent struct {
	Direction  Direction
	Time       time.Time
	RecordType uint8
	Type       HandshakeType
	Name       string
	Version    uint16
	Body       []byte
	Raw        []byte
	Encrypted  bool
}

// String renders a one-line summary followed by a truncated hex dump.
func (e HandshakeEvent) String() (text string) {
	name := e.Name
	if name == "" {
		name = e.Type.String()
	}

	version := VersionName(e.Version)
	if e.Version == 0 {
		version = "unnegotiated"
	}

	protection := "plaintext"
	if e.Encrypted {
		protection = "encrypted on the wire"
	}

	dump := e.Raw

	const maxDump = 128

	suffix := ""

	if len(dump) > maxDump {
		dump = dump[:maxDump]
		suffix = "..."
	}

	return fmt.Sprintf("%s %s (%s, %s, %d bytes): %s%s",
		e.Direction, name, version, protection, len(e.Raw), hex.EncodeToString(dump), suffix)
}

// ConnectionState is the negotiated state of a completed handshake.
type ConnectionState struct {
	Version                     uint16
	CipherSuite                 uint16
	NegotiatedProtocol          string
	ServerName                  string
	PeerCertificates            []*x509.Certificate
	VerifiedChains              [][]*x509.Certificate
	SignedCertificateTimestamps [][]byte
	OCSPResponse                []byte
	TLSUnique                   []byte
	DidResume                   bool
	HandshakeComplete           bool
	ExportCipher                bool
}

// HandshakeLog is the accumulated handshake trace.
type HandshakeLog struct {
	Events    []HandshakeEvent
	Truncated bool
}

// First returns the first event of type t, or nil.
func (l *HandshakeLog) First(t HandshakeType) (event *HandshakeEvent) {
	if l == nil {
		return nil
	}

	for i := range l.Events {
		if l.Events[i].Type == t {
			return &l.Events[i]
		}
	}

	return nil
}

// ClientHello returns the ClientHello event, or nil.
func (l *HandshakeLog) ClientHello() (event *HandshakeEvent) {
	return l.First(HandshakeClientHello)
}

// ServerHello returns the ServerHello event, or nil.
func (l *HandshakeLog) ServerHello() (event *HandshakeEvent) {
	return l.First(HandshakeServerHello)
}

// Certificates returns every Certificate message event.
func (l *HandshakeLog) Certificates() (events []HandshakeEvent) {
	return l.All(HandshakeCertificate)
}

// Finished returns every Finished message event.
func (l *HandshakeLog) Finished() (events []HandshakeEvent) {
	return l.All(HandshakeFinished)
}

// All returns every event of type t.
func (l *HandshakeLog) All(t HandshakeType) (events []HandshakeEvent) {
	if l == nil {
		return nil
	}

	for i := range l.Events {
		if l.Events[i].Type == t {
			events = append(events, l.Events[i])
		}
	}

	return events
}

// Alerts returns every alert event.
func (l *HandshakeLog) Alerts() (alerts []HandshakeEvent) {
	if l == nil {
		return nil
	}

	for i := range l.Events {
		if l.Events[i].RecordType == record.TypeAlert {
			alerts = append(alerts, l.Events[i])
		}
	}

	return alerts
}

// Clone returns a deep copy of the log's events and byte slices.
func (l *HandshakeLog) Clone() (clone *HandshakeLog) {
	if l == nil {
		return nil
	}

	clone = &HandshakeLog{
		Events:    make([]HandshakeEvent, len(l.Events)),
		Truncated: l.Truncated,
	}

	for i := range l.Events {
		clone.Events[i] = l.Events[i].clone()
	}

	return clone
}

// clone copies an event and its byte slices.
func (e *HandshakeEvent) clone() (clone HandshakeEvent) {
	clone = *e
	clone.Body = append([]byte(nil), e.Body...)
	clone.Raw = append([]byte(nil), e.Raw...)

	return clone
}
