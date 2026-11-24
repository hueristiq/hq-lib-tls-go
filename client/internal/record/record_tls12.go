package record

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // G502: legacy TLS requires DES.
	"crypto/hmac"
	"crypto/rand"
	"crypto/rc4" //nolint:gosec // G503: legacy TLS requires RC4.
	"crypto/subtle"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
	hqgotlsclientkeys "github.com/hueristiq/hq-lib-tls-go/client/internal/keys"
)

// encryptAEAD protects a TLS 1.2 AEAD record.
func (p *Protection) encryptAEAD(typ uint8, version uint16, payload []byte) (wire []byte, err error) {
	var explicitNonce []byte

	switch p.suite.Encryption {
	case "AES128-GCM", "AES256-GCM":
		explicitNonce = make([]byte, 8)

		if _, err = io.ReadFull(rand.Reader, explicitNonce); err != nil {
			return nil, hqgoerrors.Wrap(err, "generating explicit AEAD nonce")
		}
	case "CHACHA20-POLY1305":
		explicitNonce = nil
	}

	nonce := p.aeadNonce(explicitNonce)

	additional := p.additionalData(typ, version, len(payload))
	ciphertext := p.aead.Seal(nil, nonce, payload, additional)

	wire = make([]byte, 0, len(explicitNonce)+len(ciphertext))
	wire = append(wire, explicitNonce...)
	wire = append(wire, ciphertext...)

	p.seq++

	return wire, nil
}

// decryptAEAD opens a TLS 1.2 AEAD record.
func (p *Protection) decryptAEAD(typ uint8, version uint16, payload []byte) (plaintext []byte, err error) {
	explicitLen := 0
	if p.suite.Encryption == "AES128-GCM" || p.suite.Encryption == "AES256-GCM" {
		explicitLen = 8
	}

	if len(payload) < explicitLen+p.aead.Overhead() {
		return nil, hqgoerrors.New("invalid input, AEAD record is truncated")
	}

	explicitNonce := payload[:explicitLen]
	ciphertext := payload[explicitLen:]

	nonce := p.aeadNonce(explicitNonce)
	plaintextLen := len(ciphertext) - p.aead.Overhead()
	additional := p.additionalData(typ, version, plaintextLen)

	plaintext, err = p.aead.Open(nil, nonce, ciphertext, additional)
	if err != nil {
		return nil, hqgoerrors.Wrap(err, "decrypting AEAD record")
	}

	p.seq++

	return plaintext, nil
}

// aeadNonce derives the TLS 1.2 AEAD nonce.
func (p *Protection) aeadNonce(explicit []byte) (nonce []byte) {
	switch p.suite.Encryption {
	case "AES128-GCM", "AES256-GCM":
		// 4-byte fixed salt from the key block + 8-byte explicit nonce.
		nonce = make([]byte, 12)
		copy(nonce, p.iv)
		copy(nonce[4:], explicit)
	case "CHACHA20-POLY1305":
		nonce = make([]byte, 12)
		copy(nonce, p.iv)

		var seq [8]byte

		binary.BigEndian.PutUint64(seq[:], p.seq)

		for i := range 8 {
			nonce[4+i] ^= seq[i]
		}
	default:
		nonce = append([]byte(nil), p.iv...)
	}

	return nonce
}

// additionalData builds the TLS 1.2 AEAD additional data.
func (p *Protection) additionalData(typ uint8, version uint16, length int) (additional []byte) {
	additional = []byte{0, 0, 0, 0, 0, 0, 0, 0, typ, byte(version >> 8), byte(version), byte(length >> 8), byte(length)} //nolint:gosec // G115: protocol fields are bounded by their wire widths.

	binary.BigEndian.PutUint64(additional[:8], p.seq)

	return additional
}

// encryptStream protects an RC4 record.
func (p *Protection) encryptStream(typ uint8, version uint16, payload []byte) (wire []byte, err error) {
	plaintext := make([]byte, 0, len(payload)+p.macSize())
	plaintext = append(plaintext, payload...)
	plaintext = append(plaintext, p.mac(typ, version, payload)...)

	wire = make([]byte, len(plaintext))
	p.stream.XORKeyStream(wire, plaintext)

	p.seq++

	return wire, nil
}

// decryptStream opens an RC4 record.
func (p *Protection) decryptStream(typ uint8, version uint16, payload []byte) (plaintext []byte, err error) {
	buf := make([]byte, len(payload))
	p.stream.XORKeyStream(buf, payload)

	macSize := p.macSize()
	if len(buf) < macSize {
		return nil, hqgoerrors.New("invalid input, stream record is truncated")
	}

	plaintext = buf[:len(buf)-macSize]
	mac := buf[len(buf)-macSize:]

	expected := p.mac(typ, version, plaintext)
	if subtle.ConstantTimeCompare(mac, expected) != 1 {
		return nil, hqgoerrors.New("bad record MAC")
	}

	p.seq++

	return plaintext, nil
}

// encryptCBC protects a CBC record.
func (p *Protection) encryptCBC(typ uint8, version uint16, payload []byte) (wire []byte, err error) {
	blockSize := p.block.BlockSize()

	mac := p.mac(typ, version, payload)

	plaintext := make([]byte, 0, len(payload)+len(mac)+blockSize)
	plaintext = append(plaintext, payload...)
	plaintext = append(plaintext, mac...)

	paddingLen := blockSize - (len(plaintext) % blockSize)
	for range paddingLen {
		// TLS requires every padding byte to equal paddingLen-1; SSL 3.0
		// allows arbitrary bytes but also ends with paddingLen-1.
		plaintext = append(plaintext, byte(paddingLen-1)) //nolint:gosec // G115: padding length is bounded by the block size.
	}

	iv := p.ivForWrite(blockSize)

	ciphertext := make([]byte, len(plaintext))
	encrypter := cipher.NewCBCEncrypter(p.block, iv) //nolint:gosec // G407: the IV is random or the negotiated key-block IV.
	encrypter.CryptBlocks(ciphertext, plaintext)

	p.advanceIV(ciphertext, blockSize)

	if p.explicitIV(version) {
		wire = make([]byte, 0, blockSize+len(ciphertext))
		wire = append(wire, iv...)
		wire = append(wire, ciphertext...)
	} else {
		wire = ciphertext
	}

	p.seq++

	return wire, nil
}

// decryptCBC opens a CBC record.
func (p *Protection) decryptCBC(typ uint8, version uint16, payload []byte) (plaintext []byte, err error) {
	blockSize := p.block.BlockSize()

	if len(payload) == 0 || len(payload)%blockSize != 0 {
		return nil, hqgoerrors.New("invalid input, CBC record length is not a multiple of the block size")
	}

	var iv []byte

	ciphertext := payload

	if p.explicitIV(version) {
		if len(payload) < blockSize {
			return nil, hqgoerrors.New("invalid input, CBC record is missing its explicit IV")
		}

		iv = payload[:blockSize]
		ciphertext = payload[blockSize:]
	} else {
		iv = p.ivForRead(blockSize)
	}

	if len(ciphertext) == 0 {
		return nil, hqgoerrors.New("invalid input, CBC record has no ciphertext")
	}

	plaintext = make([]byte, len(ciphertext))
	decrypter := cipher.NewCBCDecrypter(p.block, iv)
	decrypter.CryptBlocks(plaintext, ciphertext)

	p.advanceIVRead(ciphertext, blockSize)

	paddingLen, paddingErr := p.checkPadding(plaintext)
	if paddingErr != nil {
		return nil, paddingErr
	}

	plaintext = plaintext[:len(plaintext)-paddingLen]

	macSize := p.macSize()
	if len(plaintext) < macSize {
		return nil, hqgoerrors.New("invalid input, CBC record is shorter than its MAC")
	}

	mac := plaintext[len(plaintext)-macSize:]
	plaintext = plaintext[:len(plaintext)-macSize]

	expected := p.mac(typ, version, plaintext)
	if subtle.ConstantTimeCompare(mac, expected) != 1 {
		return nil, hqgoerrors.New("bad record MAC")
	}

	p.seq++

	return plaintext, nil
}

// checkPadding validates CBC padding and returns its total length.
func (p *Protection) checkPadding(plaintext []byte) (paddingLen int, err error) {
	if len(plaintext) == 0 {
		return 0, hqgoerrors.New("invalid input, CBC plaintext is empty")
	}

	last := plaintext[len(plaintext)-1]

	if p.ssl3 {
		paddingLen = int(last) + 1

		if paddingLen > len(plaintext) || paddingLen > 256 {
			return 0, hqgoerrors.New("invalid input, SSL 3.0 padding is invalid")
		}

		return paddingLen, nil
	}

	if int(last)+1 > len(plaintext) || int(last)+1 > 256 {
		return 0, hqgoerrors.New("invalid input, CBC padding is invalid")
	}

	paddingLen = int(last) + 1

	for i := len(plaintext) - paddingLen; i < len(plaintext); i++ {
		if plaintext[i] != last {
			return 0, hqgoerrors.New("invalid input, CBC padding is invalid")
		}
	}

	return paddingLen, nil
}

// explicitIV reports whether version uses an explicit CBC IV.
func (p *Protection) explicitIV(version uint16) (explicit bool) {
	return version >= hqgotlsciphers.VersionTLS11 && !p.ssl3
}

// ivForWrite returns the IV for the next CBC encryption.
func (p *Protection) ivForWrite(blockSize int) (iv []byte) {
	if p.implicitIV != nil && len(p.implicitIV) == blockSize {
		return append([]byte(nil), p.implicitIV...)
	}

	iv = make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return make([]byte, blockSize)
	}

	return iv
}

// ivForRead returns the IV for the next CBC decryption.
func (p *Protection) ivForRead(blockSize int) (iv []byte) {
	if p.implicitIV != nil && len(p.implicitIV) == blockSize {
		return append([]byte(nil), p.implicitIV...)
	}

	return make([]byte, blockSize)
}

// advanceIV updates the implicit CBC IV after encryption.
func (p *Protection) advanceIV(ciphertext []byte, blockSize int) {
	if p.explicitIV(p.version) {
		return
	}

	p.implicitIV = append([]byte(nil), ciphertext[len(ciphertext)-blockSize:]...)
}

// advanceIVRead updates the implicit CBC IV after decryption.
func (p *Protection) advanceIVRead(ciphertext []byte, blockSize int) {
	if p.explicitIV(p.version) {
		return
	}

	p.implicitIV = append([]byte(nil), ciphertext[len(ciphertext)-blockSize:]...)
}

// macSize returns the MAC length for the suite.
func (p *Protection) macSize() (size int) {
	return hqgotlsclientkeys.MACLength(p.suite.Hash)
}

// mac computes the record MAC.
func (p *Protection) mac(typ uint8, version uint16, payload []byte) (mac []byte) {
	if p.ssl3 {
		return ssl3MAC(p.macKey, p.seq, typ, payload, p.suite.Hash)
	}

	newHash := hqgotlsclientkeys.HashFunc(p.suite.Hash)
	h := hmac.New(newHash, p.macKey)

	var seq [8]byte

	binary.BigEndian.PutUint64(seq[:], p.seq)

	h.Write(seq[:])
	h.Write([]byte{typ, byte(version >> 8), byte(version), byte(len(payload) >> 8), byte(len(payload))}) //nolint:gosec // G115: protocol fields are bounded by their wire widths.
	h.Write(payload)

	return h.Sum(nil)
}

// NewProtection constructs record protection from traffic keys.
func NewProtection(suite *hqgotlsciphers.Suite, version uint16, macKey, encKey, iv []byte, tls13 bool) (protection *Protection, err error) {
	protection = &Protection{
		suite:   suite,
		version: version,
		macKey:  append([]byte(nil), macKey...),
		encKey:  append([]byte(nil), encKey...),
		iv:      append([]byte(nil), iv...),
		tls13:   tls13,
		ssl3:    version == hqgotlsciphers.VersionSSL30,
	}

	switch suite.Encryption {
	case "AES128-GCM", "AES256-GCM":
		block, blockErr := aes.NewCipher(encKey)
		if blockErr != nil {
			return nil, hqgoerrors.Wrap(blockErr, "creating AES cipher")
		}

		aead, aeadErr := cipher.NewGCM(block)
		if aeadErr != nil {
			return nil, hqgoerrors.Wrap(aeadErr, "creating AES-GCM AEAD")
		}

		protection.aead = aead
	case "CHACHA20-POLY1305":
		aead, aeadErr := chacha20poly1305.New(encKey)
		if aeadErr != nil {
			return nil, hqgoerrors.Wrap(aeadErr, "creating ChaCha20-Poly1305 AEAD")
		}

		protection.aead = aead
	case "AES128-CBC", "AES256-CBC":
		block, blockErr := aes.NewCipher(encKey)
		if blockErr != nil {
			return nil, hqgoerrors.Wrap(blockErr, "creating AES cipher")
		}

		protection.block = block
	case "3DES-CBC":
		block, blockErr := des.NewTripleDESCipher(encKey) //nolint:gosec // G405: legacy TLS requires 3DES.
		if blockErr != nil {
			return nil, hqgoerrors.Wrap(blockErr, "creating 3DES cipher")
		}

		protection.block = block
	case "DES40-CBC", "DES-CBC-56":
		block, blockErr := des.NewCipher(expandDESKey(encKey)) //nolint:gosec // G405: legacy TLS requires DES.
		if blockErr != nil {
			return nil, hqgoerrors.Wrap(blockErr, "creating DES cipher")
		}

		protection.block = block
	case "RC2-CBC-40", "RC2-CBC-56":
		effectiveBits := 40
		if suite.Encryption == "RC2-CBC-56" {
			effectiveBits = 56
		}

		block, blockErr := newRC2Cipher(encKey, effectiveBits)
		if blockErr != nil {
			return nil, hqgoerrors.Wrap(blockErr, "creating RC2 cipher")
		}

		protection.block = block
	case "RC4-128", "RC4-40", "RC4-56":
		stream, streamErr := rc4.NewCipher(encKey) //nolint:gosec // G405: legacy TLS requires RC4.
		if streamErr != nil {
			return nil, hqgoerrors.Wrap(streamErr, "creating RC4 cipher")
		}

		protection.stream = stream
	default:
		return nil, hqgoerrors.Errorf("%w: %s", hqgotlsclientkeys.ErrUnsupportedCipherSuite, suite.Name)
	}

	if protection.block != nil && !protection.explicitIV(version) {
		protection.implicitIV = append([]byte(nil), iv...)
	}

	return protection, nil
}

// expandDESKey pads an export DES key to eight bytes.
func expandDESKey(key []byte) (expanded []byte) {
	expanded = make([]byte, 8)
	copy(expanded, key)

	return expanded
}
