package fingerprint

import (
	"strconv"
	"strings"
)

// greaseTable reports whether value is a reserved GREASE value (RFC 8701).
// GREASE identifiers carry no meaning and are dropped from fingerprints.
//
// Parameters:
//   - value (uint16): the identifier to test.
//
// Returns:
//   - isGrease (bool): true when value is a reserved GREASE value; otherwise, false.
func greaseTable(value uint16) (isGrease bool) {
	switch value {
	case 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa:
		isGrease = true
	}

	return isGrease
}

// joinUint16s renders values as a dash-joined decimal string, skipping
// GREASE values.
//
// Parameters:
//   - values ([]uint16): the values to render.
//
// Returns:
//   - rendered (string): the joined values; empty when none remain.
func joinUint16s(values []uint16) (rendered string) {
	parts := make([]string, 0, len(values))

	for _, value := range values {
		if greaseTable(value) {
			continue
		}

		parts = append(parts, strconv.FormatUint(uint64(value), 10))
	}

	return strings.Join(parts, "-")
}

// joinUint8s renders values as a dash-joined decimal string, skipping
// GREASE values (0x0a, 0x1a, ..., 0xfa).
//
// Parameters:
//   - values ([]byte): the values to render.
//
// Returns:
//   - rendered (string): the joined values; empty when none remain.
func joinUint8s(values []byte) (rendered string) {
	parts := make([]string, 0, len(values))

	for _, value := range values {
		if greaseTable(0x0101 * uint16(value)) {
			continue
		}

		parts = append(parts, strconv.FormatUint(uint64(value), 10))
	}

	return strings.Join(parts, "-")
}
