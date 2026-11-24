package record

import (
	"encoding/binary"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

// encryptTLS13 writes a TLS 1.3 inner plaintext.
func (p *Protection) encryptTLS13(typ uint8, payload []byte) (wire []byte, err error) {
	inner := make([]byte, 0, len(payload)+1)
	inner = append(inner, payload...)
	inner = append(inner, typ)

	ciphertextLen := len(inner) + p.aead.Overhead()

	header := [5]byte{
		TypeApplicationData,
		byte(hqgotlsciphers.VersionTLS12 >> 8),
		byte(hqgotlsciphers.VersionTLS12 & 0xff),
		byte(ciphertextLen >> 8), //nolint:gosec // G115: TLS 1.3 ciphertext is bounded by maxCiphertext.
		byte(ciphertextLen),      //nolint:gosec // G115: TLS 1.3 ciphertext is bounded by maxCiphertext.
	}

	nonce := p.nonce()
	ciphertext := p.aead.Seal(nil, nonce, inner, header[:5])

	wire = append([]byte(nil), ciphertext...)

	p.seq++

	return wire, nil
}

// decryptTLS13 opens a TLS 1.3 record.
func (p *Protection) decryptTLS13(typ uint8, payload []byte) (plaintext []byte, innerType uint8, err error) {
	header := [5]byte{typ, byte(hqgotlsciphers.VersionTLS12 >> 8), byte(hqgotlsciphers.VersionTLS12 & 0xff), byte(len(payload) >> 8), byte(len(payload))} //nolint:gosec // G115: TLS 1.3 record lengths are bounded by maxCiphertext.

	nonce := p.nonce()

	inner, err := p.aead.Open(nil, nonce, payload, header[:5])
	if err != nil {
		return nil, 0, hqgoerrors.Wrap(err, "decrypting TLS 1.3 record")
	}

	for len(inner) > 0 && inner[len(inner)-1] == 0 {
		inner = inner[:len(inner)-1]
	}

	if len(inner) == 0 {
		return nil, 0, hqgoerrors.New("invalid input, TLS 1.3 inner plaintext is empty")
	}

	innerType = inner[len(inner)-1]
	plaintext = inner[:len(inner)-1]

	p.seq++

	return plaintext, innerType, nil
}

// nonce derives the TLS 1.3 per-record nonce.
func (p *Protection) nonce() (nonce []byte) {
	nonce = make([]byte, len(p.iv))
	copy(nonce, p.iv)

	var seq [8]byte

	binary.BigEndian.PutUint64(seq[:], p.seq)

	for i := range 8 {
		nonce[len(nonce)-8+i] ^= seq[i]
	}

	return nonce
}
