package record

import (
	"crypto/cipher"
	"encoding/binary"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// rc2Table is the RC2 key-expansion permutation from RFC 2268.
var rc2Table = [256]byte{
	0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
	0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
	0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
	0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
	0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
	0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
	0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
	0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
	0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
	0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
	0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
	0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
	0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
	0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
	0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
	0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
}

// rc2Cipher is the RC2 block cipher with a 64-bit block.
type rc2Cipher struct {
	key [64]uint16
}

// newRC2Cipher creates an RC2 cipher with the given effective key bits.
func newRC2Cipher(key []byte, effectiveBits int) (block cipher.Block, err error) {
	if len(key) == 0 || len(key) > 128 {
		return nil, hqgoerrors.Errorf("invalid input, RC2 key length %d is outside 1..128", len(key))
	}

	if effectiveBits <= 0 || effectiveBits > 1024 {
		return nil, hqgoerrors.Errorf("invalid input, RC2 effective key bits %d is outside 1..1024", effectiveBits)
	}

	var expanded [128]byte

	copy(expanded[:], key)

	t := len(key)
	t8 := (effectiveBits + 7) / 8
	tm := byte(255 >> uint(8*t8-effectiveBits))

	for i := t; i < 128; i++ {
		expanded[i] = rc2Table[expanded[i-1]+expanded[i-t]]
	}

	expanded[128-t8] = rc2Table[expanded[128-t8]&tm]

	for i := 127 - t8; i >= 0; i-- {
		expanded[i] = rc2Table[expanded[i+1]^expanded[i+t8]]
	}

	cipherBlock := &rc2Cipher{}

	for i := range cipherBlock.key {
		cipherBlock.key[i] = uint16(expanded[2*i]) | uint16(expanded[2*i+1])<<8
	}

	return cipherBlock, nil
}

// BlockSize returns the RC2 block size in bytes.
func (c *rc2Cipher) BlockSize() (size int) {
	return 8
}

// Encrypt encrypts one block.
func (c *rc2Cipher) Encrypt(dst, src []byte) {
	if len(src) < 8 || len(dst) < 8 {
		panic("RC2 input not full block")
	}

	var r [4]uint16

	for i := range r {
		r[i] = binary.LittleEndian.Uint16(src[2*i:])
	}

	keyIndex := 0

	for i := range 16 {
		c.mixRound(&r, &keyIndex)

		if i == 4 || i == 10 {
			c.mashRound(&r)
		}
	}

	for i := range r {
		binary.LittleEndian.PutUint16(dst[2*i:], r[i])
	}
}

// Decrypt decrypts one block.
func (c *rc2Cipher) Decrypt(dst, src []byte) {
	if len(src) < 8 || len(dst) < 8 {
		panic("RC2 input not full block")
	}

	var r [4]uint16

	for i := range r {
		r[i] = binary.LittleEndian.Uint16(src[2*i:])
	}

	keyIndex := 63

	for i := 15; i >= 0; i-- {
		c.reverseMixRound(&r, &keyIndex)

		if i == 11 || i == 5 {
			c.reverseMashRound(&r)
		}
	}

	for i := range r {
		binary.LittleEndian.PutUint16(dst[2*i:], r[i])
	}
}

// mixRound performs one RC2 mixing round.
func (c *rc2Cipher) mixRound(r *[4]uint16, keyIndex *int) {
	x := r[0] + (r[1] &^ r[3]) + (r[2] & r[3]) + c.key[*keyIndex]
	*keyIndex++
	r[0] = rotateLeft16(x, 1)

	x = r[1] + (r[2] &^ r[0]) + (r[3] & r[0]) + c.key[*keyIndex]
	*keyIndex++
	r[1] = rotateLeft16(x, 2)

	x = r[2] + (r[3] &^ r[1]) + (r[0] & r[1]) + c.key[*keyIndex]
	*keyIndex++
	r[2] = rotateLeft16(x, 3)

	x = r[3] + (r[0] &^ r[2]) + (r[1] & r[2]) + c.key[*keyIndex]
	*keyIndex++
	r[3] = rotateLeft16(x, 5)
}

// mashRound performs one RC2 mashing round.
func (c *rc2Cipher) mashRound(r *[4]uint16) {
	r[0] += c.key[r[3]&63]
	r[1] += c.key[r[0]&63]
	r[2] += c.key[r[1]&63]
	r[3] += c.key[r[2]&63]
}

// reverseMixRound undoes one RC2 mixing round.
func (c *rc2Cipher) reverseMixRound(r *[4]uint16, keyIndex *int) {
	x := rotateRight16(r[3], 5)
	r[3] = x - ((r[0] &^ r[2]) + (r[1] & r[2]) + c.key[*keyIndex])
	*keyIndex--

	x = rotateRight16(r[2], 3)
	r[2] = x - ((r[3] &^ r[1]) + (r[0] & r[1]) + c.key[*keyIndex])
	*keyIndex--

	x = rotateRight16(r[1], 2)
	r[1] = x - ((r[2] &^ r[0]) + (r[3] & r[0]) + c.key[*keyIndex])
	*keyIndex--

	x = rotateRight16(r[0], 1)
	r[0] = x - ((r[1] &^ r[3]) + (r[2] & r[3]) + c.key[*keyIndex])
	*keyIndex--
}

// reverseMashRound undoes one RC2 mashing round.
func (c *rc2Cipher) reverseMashRound(r *[4]uint16) {
	r[3] -= c.key[r[2]&63]
	r[2] -= c.key[r[1]&63]
	r[1] -= c.key[r[0]&63]
	r[0] -= c.key[r[3]&63]
}

// rotateLeft16 rotates value left by shift bits.
func rotateLeft16(value uint16, shift uint) (rotated uint16) {
	return value<<shift | value>>(16-shift)
}

// rotateRight16 rotates value right by shift bits.
func rotateRight16(value uint16, shift uint) (rotated uint16) {
	return value>>shift | value<<(16-shift)
}
