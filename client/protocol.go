package client

import (
	"github.com/hueristiq/hq-lib-tls-go/client/internal/message"
)

// HandshakeType identifies a handshake message.
type HandshakeType uint8

// Handshake message types.
const (
	HandshakeClientHello         HandshakeType = 1
	HandshakeServerHello         HandshakeType = 2
	HandshakeNewSessionTicket    HandshakeType = 4
	HandshakeEndOfEarlyData      HandshakeType = 5
	HandshakeEncryptedExtensions HandshakeType = 8
	HandshakeCertificate         HandshakeType = 11
	HandshakeServerKeyExchange   HandshakeType = 12
	HandshakeCertificateRequest  HandshakeType = 13
	HandshakeServerHelloDone     HandshakeType = 14
	HandshakeCertificateVerify   HandshakeType = 15
	HandshakeClientKeyExchange   HandshakeType = 16
	HandshakeFinished            HandshakeType = 20
	HandshakeCertificateStatus   HandshakeType = 22
	HandshakeKeyUpdate           HandshakeType = 24
	HandshakeMessageHash         HandshakeType = 254
)

// String returns the handshake message name.
func (t HandshakeType) String() (name string) {
	switch t {
	case HandshakeClientHello:
		name = "ClientHello"
	case HandshakeServerHello:
		name = "ServerHello"
	case HandshakeNewSessionTicket:
		name = "NewSessionTicket"
	case HandshakeEndOfEarlyData:
		name = "EndOfEarlyData"
	case HandshakeEncryptedExtensions:
		name = "EncryptedExtensions"
	case HandshakeCertificate:
		name = "Certificate"
	case HandshakeServerKeyExchange:
		name = "ServerKeyExchange"
	case HandshakeCertificateRequest:
		name = "CertificateRequest"
	case HandshakeServerHelloDone:
		name = "ServerHelloDone"
	case HandshakeCertificateVerify:
		name = "CertificateVerify"
	case HandshakeClientKeyExchange:
		name = "ClientKeyExchange"
	case HandshakeFinished:
		name = "Finished"
	case HandshakeCertificateStatus:
		name = "CertificateStatus"
	case HandshakeKeyUpdate:
		name = "KeyUpdate"
	case HandshakeMessageHash:
		name = "MessageHash"
	default:
		name = "Unknown"
	}

	return name
}

// marshalHandshake prepends the four-byte handshake header to body.
func marshalHandshake(typ HandshakeType, body []byte) (raw []byte) {
	return message.MarshalHandshake(uint8(typ), body)
}
