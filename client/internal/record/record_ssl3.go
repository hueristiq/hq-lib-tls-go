package record

import (
	"encoding/binary"

	hqgotlsclientkeys "github.com/hueristiq/hq-lib-tls-go/client/internal/keys"
)

// ssl3MAC computes the SSL 3.0 record MAC.
func ssl3MAC(macKey []byte, seq uint64, typ uint8, payload []byte, hashName string) (mac []byte) {
	padLen := 48

	pad1 := make([]byte, padLen)
	pad2 := make([]byte, padLen)

	for i := range pad1 {
		pad1[i] = 0x36
		pad2[i] = 0x5c
	}

	var seqBytes [8]byte

	binary.BigEndian.PutUint64(seqBytes[:], seq)

	inner := make([]byte, 0, len(macKey)+padLen+8+5+len(payload))
	inner = append(inner, macKey...)
	inner = append(inner, pad1...)
	inner = append(inner, seqBytes[:]...)
	inner = append(inner, typ, byte(len(payload)>>8), byte(len(payload))) //nolint:gosec // G115: SSL 3.0 MAC input lengths are bounded by the record size.
	inner = append(inner, payload...)

	innerHash := hqgotlsclientkeys.HashFunc(hashName)()
	innerHash.Write(inner)

	innerSum := innerHash.Sum(nil)

	outer := make([]byte, 0, len(macKey)+padLen+len(innerSum))
	outer = append(outer, macKey...)
	outer = append(outer, pad2...)
	outer = append(outer, innerSum...)

	outerHash := hqgotlsclientkeys.HashFunc(hashName)()
	outerHash.Write(outer)

	return outerHash.Sum(nil)
}
