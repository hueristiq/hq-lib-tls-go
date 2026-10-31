package fingerprint

import (
	"errors"
	"fmt"
	"strconv"
)

// JA3S computes the JA3S segment of a captured ServerHello: the decimal
// TLS version, the selected cipher suite, and the dash-joined extension
// types, separated by commas. GREASE values are dropped.
//
// Parameters:
//   - raw ([]byte): the ServerHello handshake message, with its four-byte
//     handshake header, as captured by the parent client package.
//
// Returns:
//   - ja3s (string): the JA3S segment, ready for [Digest].
//   - err (error): non-nil when the message is truncated or malformed.
func JA3S(raw []byte) (ja3s string, err error) {
	body, err := handshakeBody(raw)
	if err != nil {
		err = fmt.Errorf("fingerprint.JA3S: %w", err)

		return "", err
	}

	offset := 0

	if offset+2 > len(body) {
		return "", errors.New("fingerprint.JA3S: invalid input, ServerHello is truncated at the version field")
	}

	version := uint16(body[offset])<<8 | uint16(body[offset+1])

	offset += 2

	// random (32 bytes)
	offset += 32

	// session ID
	offset, _, err = readVariable(body, offset, 1)
	if err != nil {
		err = fmt.Errorf("fingerprint.JA3S: reading session ID: %w", err)

		return "", err
	}

	if offset+3 > len(body) {
		return "", errors.New("fingerprint.JA3S: invalid input, ServerHello is truncated at the cipher suite field")
	}

	cipherSuite := uint16(body[offset])<<8 | uint16(body[offset+1])

	offset += 2

	// compression method (1 byte)
	offset++

	// extensions
	var extensions []byte

	if offset < len(body) {
		_, extensions, err = readVariable(body, offset, 2)
		if err != nil {
			err = fmt.Errorf("fingerprint.JA3S: reading extensions: %w", err)

			return "", err
		}
	}

	extensionTypes, _, _ := parseExtensions(extensions)

	ja3s = strconv.FormatUint(uint64(version), 10) + "," +
		strconv.FormatUint(uint64(cipherSuite), 10) + "," +
		joinUint16s(extensionTypes)

	return ja3s, nil
}
