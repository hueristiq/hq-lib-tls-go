package message

import (
	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// AppendUint8 appends value as one byte.
func AppendUint8(raw []byte, value uint8) (extended []byte) {
	return append(raw, value)
}

// AppendUint16 appends value in big-endian order.
func AppendUint16(raw []byte, value uint16) (extended []byte) {
	return append(raw, byte(value>>8), byte(value)) //nolint:gosec // G115: explicit big-endian encoding.
}

// AppendUint24 appends value in big-endian order over three bytes.
func AppendUint24(raw []byte, value uint32) (extended []byte) {
	return append(raw, byte(value>>16), byte(value>>8), byte(value)) //nolint:gosec // G115: explicit big-endian encoding.
}

// AppendVector8 appends a one-byte length followed by data.
func AppendVector8(raw, data []byte) (extended []byte, err error) {
	if len(data) > 0xff {
		return nil, hqgoerrors.Errorf("length %d does not fit in one byte", len(data))
	}

	extended = AppendUint8(raw, uint8(len(data))) //nolint:gosec // G115: length is bounded by the check above.

	return append(extended, data...), nil
}

// AppendVector16 appends a two-byte length followed by data.
func AppendVector16(raw, data []byte) (extended []byte, err error) {
	if len(data) > 0xffff {
		return nil, hqgoerrors.Errorf("length %d does not fit in two bytes", len(data))
	}

	extended = AppendUint16(raw, uint16(len(data))) //nolint:gosec // G115: length is bounded by the check above.

	return append(extended, data...), nil
}

// AppendVector24 appends a three-byte length followed by data.
func AppendVector24(raw, data []byte) (extended []byte, err error) {
	if len(data) > 0xffffff {
		return nil, hqgoerrors.Errorf("length %d does not fit in three bytes", len(data))
	}

	extended = AppendUint24(raw, uint32(len(data))) //nolint:gosec // G115: length is bounded by the check above.

	return append(extended, data...), nil
}

// MarshalHandshake prepends the four-byte handshake header to body.
func MarshalHandshake(typ uint8, body []byte) (raw []byte) {
	raw = make([]byte, 4, 4+len(body))
	raw[0] = typ
	raw[1] = byte(len(body) >> 16) //nolint:gosec // G115: handshake bodies are bounded by the protocol.
	raw[2] = byte(len(body) >> 8)  //nolint:gosec // G115: handshake bodies are bounded by the protocol.
	raw[3] = byte(len(body))       //nolint:gosec // G115: handshake bodies are bounded by the protocol.
	raw = append(raw, body...)

	return raw
}

// Reader is a bounds-checked cursor over a byte slice.
type Reader struct {
	data   []byte
	offset int
	err    error
}

// NewReader returns a reader over data.
func NewReader(data []byte) (r *Reader) {
	r = &Reader{data: data}

	return r
}

// Offset returns the current read offset.
func (r *Reader) Offset() (offset int) {
	return r.offset
}

// Remaining returns the number of unread bytes.
func (r *Reader) Remaining() (count int) {
	if r.err != nil {
		return 0
	}

	return len(r.data) - r.offset
}

// Uint8 reads one byte.
func (r *Reader) Uint8() (value uint8) {
	if r.err != nil {
		return 0
	}

	if r.offset+1 > len(r.data) {
		r.err = hqgoerrors.New("invalid input, buffer is truncated at a byte field")

		return 0
	}

	value = r.data[r.offset]
	r.offset++

	return value
}

// Uint16 reads two big-endian bytes.
func (r *Reader) Uint16() (value uint16) {
	if r.err != nil {
		return 0
	}

	if r.offset+2 > len(r.data) {
		r.err = hqgoerrors.New("invalid input, buffer is truncated at a two-byte field")

		return 0
	}

	value = uint16(r.data[r.offset])<<8 | uint16(r.data[r.offset+1])
	r.offset += 2

	return value
}

// Uint24 reads three big-endian bytes.
func (r *Reader) Uint24() (value uint32) {
	if r.err != nil {
		return 0
	}

	if r.offset+3 > len(r.data) {
		r.err = hqgoerrors.New("invalid input, buffer is truncated at a three-byte field")

		return 0
	}

	value = uint32(r.data[r.offset])<<16 | uint32(r.data[r.offset+1])<<8 | uint32(r.data[r.offset+2])
	r.offset += 3

	return value
}

// Bytes reads count bytes.
func (r *Reader) Bytes(count int) (value []byte) {
	if r.err != nil {
		return nil
	}

	if count < 0 || r.offset+count > len(r.data) {
		r.err = hqgoerrors.Errorf("invalid input, buffer is truncated at a %d-byte field", count)

		return nil
	}

	value = r.data[r.offset : r.offset+count]
	r.offset += count

	return value
}

// Vector8 reads a one-byte length followed by that many bytes.
func (r *Reader) Vector8() (value []byte) {
	return r.Bytes(int(r.Uint8()))
}

// Vector16 reads a two-byte length followed by that many bytes.
func (r *Reader) Vector16() (value []byte) {
	return r.Bytes(int(r.Uint16()))
}

// Vector24 reads a three-byte length followed by that many bytes.
func (r *Reader) Vector24() (value []byte) {
	return r.Bytes(int(r.Uint24()))
}

// Error returns the first read error.
func (r *Reader) Error() (err error) {
	return r.err
}
