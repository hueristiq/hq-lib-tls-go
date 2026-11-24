package client

import (
	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	"github.com/hueristiq/hq-lib-tls-go/client/internal/message"
)

// marshalSNI builds the server_name extension body.
func marshalSNI(host string) (body []byte) {
	entry, _ := message.AppendVector8([]byte{0}, []byte(host))
	body, _ = message.AppendVector16(nil, entry)

	return body
}

// marshalGroups builds the supported_groups extension body.
func marshalGroups(groups []CurveID) (body []byte) {
	raw := make([]byte, 0, len(groups)*2)

	for _, group := range groups {
		raw = message.AppendUint16(raw, uint16(group))
	}

	body, _ = message.AppendVector16(nil, raw)

	return body
}

// marshalSignatureAlgorithms builds the signature_algorithms extension body.
func marshalSignatureAlgorithms(algorithms []SignatureScheme) (body []byte) {
	raw := make([]byte, 0, len(algorithms)*2)

	for _, algorithm := range algorithms {
		raw = message.AppendUint16(raw, uint16(algorithm))
	}

	body, _ = message.AppendVector16(nil, raw)

	return body
}

// marshalALPN builds the ALPN extension body.
func marshalALPN(protocols []string) (body []byte) {
	var list []byte

	for _, protocol := range protocols {
		list, _ = message.AppendVector8(list, []byte(protocol))
	}

	body, _ = message.AppendVector16(nil, list)

	return body
}

// marshalSupportedVersions builds the supported_versions extension body.
func marshalSupportedVersions(maxVersion, minVersion uint16) (body []byte) {
	var versions []byte

	for version := maxVersion; version >= minVersion; version-- {
		versions = message.AppendUint16(versions, version)

		if version == minVersion {
			break
		}
	}

	body, _ = message.AppendVector8(nil, versions)

	return body
}

// marshalKeyShares builds the key_share extension body.
func marshalKeyShares(shares []keyShareEntry) (body []byte) {
	var list []byte

	for _, share := range shares {
		entry := message.AppendUint16(nil, share.Group)
		entry, _ = message.AppendVector16(entry, share.Data)

		list = append(list, entry...)
	}

	body, _ = message.AppendVector16(nil, list)

	return body
}

// marshalExtensions serializes an extension block.
func marshalExtensions(extensions []extensionInfo) (raw []byte, err error) {
	var block []byte

	for _, extension := range extensions {
		block = message.AppendUint16(block, extension.Type)

		var body []byte

		body, err = message.AppendVector16(block, extension.Data)
		if err != nil {
			return nil, hqgoerrors.Wrapf(err, "marshaling extension %#x", extension.Type)
		}

		block = body
	}

	raw, err = message.AppendVector16(nil, block)
	if err != nil {
		return nil, err
	}

	return raw, nil
}
