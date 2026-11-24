package client

import (
	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	"github.com/hueristiq/hq-lib-tls-go/client/internal/message"
)

// TLS extension types used by the client.
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedGroups         uint16 = 10
	extensionECPointFormats          uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionEncryptThenMAC          uint16 = 22
	extensionExtendedMasterSecret    uint16 = 23
	extensionRecordSizeLimit         uint16 = 28
	extensionSessionTicket           uint16 = 35
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKKeyExchangeModes     uint16 = 45
	extensionKeyShare                uint16 = 51
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionRenegotiationInfo       uint16 = 0xff01
)

// greaseValues are the reserved GREASE code points from RFC 8701.
var greaseValues = []uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

// HelloSpec describes a complete ClientHello. When supplied to Config,
// the engine generates key_share private keys (replacing any key_share
// extension body) and, when GREASE is set, inserts GREASE cipher suites and
// extensions. The remaining fields are used as given.
type HelloSpec struct {
	TLSVersMin         uint16
	TLSVersMax         uint16
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []Extension
	GREASE             bool
}

// Extension is one ClientHello extension.
type Extension interface {
	ExtensionType() uint16
	Marshal() ([]byte, error)
}

// GenericExtension carries an arbitrary extension body.
type GenericExtension struct {
	TypeID uint16
	Data   []byte
}

// ExtensionType returns the extension type.
func (e GenericExtension) ExtensionType() (extensionType uint16) {
	return e.TypeID
}

// Marshal returns the extension body.
func (e GenericExtension) Marshal() (body []byte, err error) {
	return append([]byte(nil), e.Data...), nil
}

// KeyShare is one key_share entry.
type KeyShare struct {
	Group CurveID
	Data  []byte
}

// SNIExtension carries the server_name extension.
type SNIExtension struct {
	HostName string
}

// ExtensionType returns the extension type.
func (e SNIExtension) ExtensionType() (extensionType uint16) {
	return extensionServerName
}

// Marshal returns the extension body.
func (e SNIExtension) Marshal() (body []byte, err error) {
	host := []byte(e.HostName)

	entry, err := message.AppendVector8([]byte{0}, host) // name_type 0 = host_name
	if err != nil {
		return nil, err
	}

	body, err = message.AppendVector16(nil, entry)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// ALPNExtension carries the application_layer_protocol_negotiation extension.
type ALPNExtension struct {
	Protocols []string
}

// ExtensionType returns the extension type.
func (e ALPNExtension) ExtensionType() (extensionType uint16) {
	return extensionALPN
}

// Marshal returns the extension body.
func (e ALPNExtension) Marshal() (body []byte, err error) {
	var list []byte

	for _, protocol := range e.Protocols {
		list, err = message.AppendVector8(list, []byte(protocol))
		if err != nil {
			return nil, err
		}
	}

	return message.AppendVector16(nil, list)
}

// SupportedGroupsExtension carries the supported_groups extension.
type SupportedGroupsExtension struct {
	Groups []CurveID
}

// ExtensionType returns the extension type.
func (e SupportedGroupsExtension) ExtensionType() (extensionType uint16) {
	return extensionSupportedGroups
}

// Marshal returns the extension body.
func (e SupportedGroupsExtension) Marshal() (body []byte, err error) {
	raw := make([]byte, 0, len(e.Groups)*2)

	for _, group := range e.Groups {
		raw = message.AppendUint16(raw, uint16(group))
	}

	return message.AppendVector16(nil, raw)
}

// SignatureAlgorithmsExtension carries the signature_algorithms extension.
type SignatureAlgorithmsExtension struct {
	Algorithms []SignatureScheme
}

// ExtensionType returns the extension type.
func (e SignatureAlgorithmsExtension) ExtensionType() (extensionType uint16) {
	return extensionSignatureAlgorithms
}

// Marshal returns the extension body.
func (e SignatureAlgorithmsExtension) Marshal() (body []byte, err error) {
	raw := make([]byte, 0, len(e.Algorithms)*2)

	for _, algorithm := range e.Algorithms {
		raw = message.AppendUint16(raw, uint16(algorithm))
	}

	return message.AppendVector16(nil, raw)
}

// SupportedVersionsExtension carries the supported_versions extension.
type SupportedVersionsExtension struct {
	Versions []uint16
}

// ExtensionType returns the extension type.
func (e SupportedVersionsExtension) ExtensionType() (extensionType uint16) {
	return extensionSupportedVersions
}

// Marshal returns the extension body.
func (e SupportedVersionsExtension) Marshal() (body []byte, err error) {
	raw := make([]byte, 0, len(e.Versions)*2)

	for _, version := range e.Versions {
		raw = message.AppendUint16(raw, version)
	}

	return message.AppendVector8(nil, raw)
}

// KeyShareExtension carries the key_share extension.
type KeyShareExtension struct {
	Shares []KeyShare
}

// ExtensionType returns the extension type.
func (e KeyShareExtension) ExtensionType() (extensionType uint16) {
	return extensionKeyShare
}

// Marshal returns the extension body.
func (e KeyShareExtension) Marshal() (body []byte, err error) {
	var list []byte

	for _, share := range e.Shares {
		entry := message.AppendUint16(nil, uint16(share.Group))

		entry, err = message.AppendVector16(entry, share.Data)
		if err != nil {
			return nil, err
		}

		list = append(list, entry...)
	}

	return message.AppendVector16(nil, list)
}

// SessionTicketExtension carries the session_ticket extension.
type SessionTicketExtension struct {
	Ticket []byte
}

// ExtensionType returns the extension type.
func (e SessionTicketExtension) ExtensionType() (extensionType uint16) {
	return extensionSessionTicket
}

// Marshal returns the extension body.
func (e SessionTicketExtension) Marshal() (body []byte, err error) {
	return append([]byte(nil), e.Ticket...), nil
}

// StatusRequestExtension carries the status_request extension.
type StatusRequestExtension struct{}

// ExtensionType returns the extension type.
func (e StatusRequestExtension) ExtensionType() (extensionType uint16) {
	return extensionStatusRequest
}

// Marshal returns the extension body.
func (e StatusRequestExtension) Marshal() (body []byte, err error) {
	// status_type = ocsp(1), responder_id_list empty, request_extensions empty.
	return []byte{1, 0, 0, 0, 0}, nil
}

// RenegotiationInfoExtension carries the renegotiation_info extension.
type RenegotiationInfoExtension struct {
	Data []byte
}

// ExtensionType returns the extension type.
func (e RenegotiationInfoExtension) ExtensionType() (extensionType uint16) {
	return extensionRenegotiationInfo
}

// Marshal returns the extension body.
func (e RenegotiationInfoExtension) Marshal() (body []byte, err error) {
	return message.AppendVector8(nil, e.Data)
}

// ExtendedMasterSecretExtension carries the extended_master_secret extension.
type ExtendedMasterSecretExtension struct{}

// ExtensionType returns the extension type.
func (e ExtendedMasterSecretExtension) ExtensionType() (extensionType uint16) {
	return extensionExtendedMasterSecret
}

// Marshal returns the extension body.
func (e ExtendedMasterSecretExtension) Marshal() (body []byte, err error) {
	return nil, nil
}

// EncryptThenMACExtension carries the encrypt_then_mac extension.
type EncryptThenMACExtension struct{}

// ExtensionType returns the extension type.
func (e EncryptThenMACExtension) ExtensionType() (extensionType uint16) {
	return extensionEncryptThenMAC
}

// Marshal returns the extension body.
func (e EncryptThenMACExtension) Marshal() (body []byte, err error) {
	return nil, nil
}

// RecordSizeLimitExtension carries the record_size_limit extension.
type RecordSizeLimitExtension struct {
	Limit uint16
}

// ExtensionType returns the extension type.
func (e RecordSizeLimitExtension) ExtensionType() (extensionType uint16) {
	return extensionRecordSizeLimit
}

// Marshal returns the extension body.
func (e RecordSizeLimitExtension) Marshal() (body []byte, err error) {
	return message.AppendUint16(nil, e.Limit), nil
}

// validate checks the spec's version range and required extensions.
func (s *HelloSpec) validate() (err error) {
	if s.TLSVersMin == 0 {
		s.TLSVersMin = VersionTLS10
	}

	if s.TLSVersMax == 0 {
		s.TLSVersMax = VersionTLS12
	}

	if !validVersion(s.TLSVersMin) || !validVersion(s.TLSVersMax) {
		err = hqgoerrors.Errorf("%w: %#x-%#x", ErrInvalidClientHelloSpec, s.TLSVersMin, s.TLSVersMax)

		return err
	}

	if s.TLSVersMin > s.TLSVersMax {
		err = hqgoerrors.Errorf("%w: minimum version %#x exceeds maximum %#x", ErrInvalidClientHelloSpec, s.TLSVersMin, s.TLSVersMax)

		return err
	}

	if s.TLSVersMax >= VersionTLS13 && !hasExtension(s.Extensions, extensionSupportedVersions) {
		err = hqgoerrors.Errorf("%w: TLS 1.3 requires the supported_versions extension", ErrInvalidClientHelloSpec)

		return err
	}

	return nil
}

// hasExtension reports whether extensions contains typeID.
func hasExtension(extensions []Extension, typeID uint16) (found bool) {
	for _, extension := range extensions {
		if extension.ExtensionType() == typeID {
			return true
		}
	}

	return false
}
