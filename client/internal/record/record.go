package record

import (
	"crypto/cipher"
	"crypto/rc4" //nolint:gosec // G503: legacy TLS requires RC4.
	"io"
	"net"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

// MaxPayload is the largest TLSPlaintext/TLSCiphertext fragment.
const MaxPayload = 1 << 14 // 16384

// maxCiphertext allows for expansion, MACs, padding, and explicit IVs.
const maxCiphertext = MaxPayload + 2048

// TLS record content types.
const (
	TypeChangeCipherSpec uint8 = 20
	TypeAlert            uint8 = 21
	TypeHandshake        uint8 = 22
	TypeApplicationData  uint8 = 23
)

// State reads and writes records in one direction.
type State struct {
	Conn       net.Conn
	Version    uint16
	Protection *Protection
	TLS13      bool
}

// Protection holds the active traffic keys for one direction.
type Protection struct {
	suite   *hqgotlsciphers.Suite
	version uint16
	macKey  []byte
	encKey  []byte
	iv      []byte
	aead    cipher.AEAD
	block   cipher.Block
	stream  *rc4.Cipher
	ssl3    bool
	tls13   bool
	seq     uint64
	// implicitIV is the CBC chaining value for SSL 3.0 and TLS 1.0.
	implicitIV []byte
}

// ReadRecord reads one record, decrypts it, and returns its content type and
// plaintext payload.
func (r *State) ReadRecord() (typ uint8, payload []byte, err error) {
	var header [5]byte

	if _, err = io.ReadFull(r.Conn, header[:]); err != nil {
		err = hqgoerrors.Wrap(err, "reading record header")

		return 0, nil, err
	}

	typ = header[0]
	recordVersion := uint16(header[1])<<8 | uint16(header[2])
	length := int(header[3])<<8 | int(header[4])

	if length > maxCiphertext {
		err = hqgoerrors.Errorf("invalid input, record length %d exceeds the maximum", length)

		return 0, nil, err
	}

	payload = make([]byte, length)

	if _, err = io.ReadFull(r.Conn, payload); err != nil {
		err = hqgoerrors.Wrap(err, "reading record payload")

		return 0, nil, err
	}

	if r.Version == 0 {
		r.Version = recordVersion
	}

	if r.Protection != nil {
		// TLS 1.3 compatibility ChangeCipherSpec records are plaintext and
		// must be ignored without decryption (RFC 8446, Appendix D.4).
		if r.TLS13 && typ == TypeChangeCipherSpec {
			return typ, payload, nil
		}

		payload, typ, err = r.Protection.decrypt(typ, recordVersion, payload)
		if err != nil {
			return 0, nil, err
		}
	}

	return typ, payload, nil
}

// WriteRecord encrypts and writes one record.
func (r *State) WriteRecord(typ uint8, payload []byte) (err error) {
	if len(payload) > MaxPayload {
		err = hqgoerrors.Errorf("invalid input, record payload %d exceeds the maximum", len(payload))

		return err
	}

	recordVersion := r.Version
	if recordVersion == 0 {
		recordVersion = hqgotlsciphers.VersionTLS10
	}

	outerType := typ
	wire := payload

	if r.Protection != nil {
		wire, err = r.Protection.encrypt(typ, recordVersion, payload)
		if err != nil {
			return err
		}

		if r.Protection.tls13 {
			outerType = TypeApplicationData
			recordVersion = hqgotlsciphers.VersionTLS12
		}
	}

	header := [5]byte{
		outerType,
		byte(recordVersion >> 8),
		byte(recordVersion),  //nolint:gosec // G115: record versions are two bytes.
		byte(len(wire) >> 8), //nolint:gosec // G115: record length is bounded by maxCiphertext.
		byte(len(wire)),      //nolint:gosec // G115: record length is bounded by maxCiphertext.
	}

	if _, err = r.Conn.Write(header[:]); err != nil {
		err = hqgoerrors.Wrap(err, "writing record header")

		return err
	}

	if _, err = r.Conn.Write(wire); err != nil {
		err = hqgoerrors.Wrap(err, "writing record payload")

		return err
	}

	return nil
}

// encrypt protects payload for the wire.
func (p *Protection) encrypt(typ uint8, version uint16, payload []byte) (wire []byte, err error) {
	if p.tls13 {
		return p.encryptTLS13(typ, payload)
	}

	if p.aead != nil {
		return p.encryptAEAD(typ, version, payload)
	}

	if p.stream != nil {
		return p.encryptStream(typ, version, payload)
	}

	return p.encryptCBC(typ, version, payload)
}

// decrypt removes protection from payload.
func (p *Protection) decrypt(typ uint8, version uint16, payload []byte) (plaintext []byte, innerType uint8, err error) {
	if p.tls13 {
		return p.decryptTLS13(typ, payload)
	}

	if p.aead != nil {
		plaintext, err = p.decryptAEAD(typ, version, payload)

		return plaintext, typ, err
	}

	if p.stream != nil {
		plaintext, err = p.decryptStream(typ, version, payload)

		return plaintext, typ, err
	}

	plaintext, err = p.decryptCBC(typ, version, payload)

	return plaintext, typ, err
}
