package fingerprint

import (
	"errors"
	"fmt"
	"strconv"
)

const (
	// handshakeHeaderLength is the length of a TLS handshake message header.
	handshakeHeaderLength = 4
	// extensionSupportedGroups is the supported_groups extension type.
	extensionSupportedGroups = 10
	// extensionPointFormats is the ec_point_formats extension type.
	extensionPointFormats = 11
)

// JA3 computes the JA3 segment of a captured ClientHello: the decimal TLS
// version, the dash-joined cipher suites, extension types, elliptic
// curves, and point formats, separated by commas. GREASE values are
// dropped, per the JA3 specification.
//
// Parameters:
//   - raw ([]byte): the ClientHello handshake message, with its four-byte
//     handshake header, as captured by the parent probe package.
//
// Returns:
//   - ja3 (string): the JA3 segment, ready for [Digest].
//   - err (error): non-nil when the message is truncated or malformed.
func JA3(raw []byte) (ja3 string, err error) {
	body, err := handshakeBody(raw)
	if err != nil {
		err = fmt.Errorf("fingerprint.JA3: %w", err)

		return "", err
	}

	offset := 0

	if offset+2 > len(body) {
		return "", errors.New("fingerprint.JA3: invalid input, ClientHello is truncated at the version field")
	}

	version := uint16(body[offset])<<8 | uint16(body[offset+1])

	offset += 2

	// random (32 bytes)
	offset += 32

	// session ID
	offset, _, err = readVariable(body, offset, 1)
	if err != nil {
		err = fmt.Errorf("fingerprint.JA3: reading session ID: %w", err)

		return "", err
	}

	// cipher suites
	offset, suites, err := readVariable(body, offset, 2)
	if err != nil {
		err = fmt.Errorf("fingerprint.JA3: reading cipher suites: %w", err)

		return "", err
	}

	cipherSuites := make([]uint16, 0, len(suites)/2)

	for i := 0; i+1 < len(suites); i += 2 {
		cipherSuites = append(cipherSuites, uint16(suites[i])<<8|uint16(suites[i+1]))
	}

	// compression methods
	offset, _, err = readVariable(body, offset, 1)
	if err != nil {
		err = fmt.Errorf("fingerprint.JA3: reading compression methods: %w", err)

		return "", err
	}

	// extensions
	var extensions []byte

	extensionsPresent := offset < len(body)

	if extensionsPresent {
		_, extensions, err = readVariable(body, offset, 2)
		if err != nil {
			err = fmt.Errorf("fingerprint.JA3: reading extensions: %w", err)

			return "", err
		}
	}

	extensionTypes, curves, pointFormats := parseExtensions(extensions)

	ja3 = strconv.FormatUint(uint64(version), 10) + "," +
		joinUint16s(cipherSuites) + "," +
		joinUint16s(extensionTypes) + "," +
		joinUint16s(curves) + "," +
		joinUint8s(pointFormats)

	return ja3, nil
}

// parseExtensions walks an extension block, collecting the extension type
// IDs in wire order plus the supported groups and point formats carried by
// the curve-related extensions.
//
// Parameters:
//   - extensions ([]byte): the extension block.
//
// Returns:
//   - types ([]uint16): the extension type IDs.
//   - curves ([]uint16): the supported groups.
//   - pointFormats ([]byte): the point formats.
func parseExtensions(extensions []byte) (types, curves []uint16, pointFormats []byte) {
	for offset := 0; offset+4 <= len(extensions); {
		extensionType := uint16(extensions[offset])<<8 | uint16(extensions[offset+1])
		length := int(extensions[offset+2])<<8 | int(extensions[offset+3])

		types = append(types, extensionType)

		offset += 4

		if offset+length > len(extensions) {
			break
		}

		data := extensions[offset : offset+length]

		switch extensionType {
		case extensionSupportedGroups:
			if len(data) >= 2 {
				count := int(data[0])<<8 | int(data[1])

				for i := 2; i+1 < len(data) && i < 2+count; i += 2 {
					curves = append(curves, uint16(data[i])<<8|uint16(data[i+1]))
				}
			}
		case extensionPointFormats:
			if len(data) >= 1 {
				count := int(data[0])

				if 1+count <= len(data) {
					pointFormats = append(pointFormats, data[1:1+count]...)
				}
			}
		}

		offset += length
	}

	return types, curves, pointFormats
}

// handshakeBody validates the handshake header and returns the message
// body.
//
// Parameters:
//   - raw ([]byte): the handshake message.
//
// Returns:
//   - body ([]byte): the message body.
//   - err (error): non-nil when raw is truncated.
func handshakeBody(raw []byte) (body []byte, err error) {
	if len(raw) < handshakeHeaderLength {
		err = errors.New("fingerprint.handshakeBody: invalid input, handshake message is truncated")

		return nil, err
	}

	length := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])

	if handshakeHeaderLength+length > len(raw) {
		err = errors.New("fingerprint.handshakeBody: invalid input, handshake message body is truncated")

		return nil, err
	}

	return raw[handshakeHeaderLength : handshakeHeaderLength+length], nil
}

// readVariable reads a length-prefixed variable: a length field of
// lengthBytes bytes followed by that many bytes of data.
//
// Parameters:
//   - body ([]byte): the buffer to read from.
//   - offset (int): the offset of the length field.
//   - lengthBytes (int): the width of the length field, in bytes.
//
// Returns:
//   - next (int): the offset after the data.
//   - data ([]byte): the read data.
//   - err (error): non-nil when the buffer is truncated.
func readVariable(body []byte, offset, lengthBytes int) (next int, data []byte, err error) {
	if offset+lengthBytes > len(body) {
		err = errors.New("fingerprint.readVariable: invalid input, buffer is truncated at a length field")

		return 0, nil, err
	}

	length := 0

	for i := range lengthBytes {
		length = length<<8 | int(body[offset+i])
	}

	start := offset + lengthBytes
	end := start + length

	if end > len(body) {
		err = errors.New("fingerprint.readVariable: invalid input, buffer is truncated inside variable-length data")

		return 0, nil, err
	}

	return end, body[start:end], nil
}
