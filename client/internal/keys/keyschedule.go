package keys

import (
	"crypto/hmac"
	"hash"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

// Schedule holds the TLS 1.3 key schedule.
type Schedule struct {
	HashName string
	HashLen  int

	HandshakeSecret []byte
	MasterSecret    []byte

	ClientHandshakeSecret []byte
	ServerHandshakeSecret []byte
}

// NewSchedule derives the handshake and master secrets from the ECDHE
// shared secret and the ClientHello..ServerHello transcript.
func NewSchedule(HashName string, sharedSecret, transcript []byte) (schedule *Schedule) {
	newHash := hashFunc(HashName)

	HashLen := 32
	if HashName == "SHA384" {
		HashLen = 48
	}

	zeros := make([]byte, HashLen)
	emptyHash := transcriptHash(HashName, nil)

	earlySecret := hkdfExtract(newHash, zeros, zeros)
	derived := hkdfExpandLabel(newHash, earlySecret, "derived", emptyHash, HashLen)
	HandshakeSecret := hkdfExtract(newHash, derived, sharedSecret)

	ClientHandshakeSecret := deriveSecret(newHash, HashName, HandshakeSecret, "c hs traffic", transcript)
	ServerHandshakeSecret := deriveSecret(newHash, HashName, HandshakeSecret, "s hs traffic", transcript)

	derived2 := hkdfExpandLabel(newHash, HandshakeSecret, "derived", emptyHash, HashLen)
	MasterSecret := hkdfExtract(newHash, derived2, zeros)

	schedule = &Schedule{
		HashName:              HashName,
		HashLen:               HashLen,
		HandshakeSecret:       HandshakeSecret,
		MasterSecret:          MasterSecret,
		ClientHandshakeSecret: ClientHandshakeSecret,
		ServerHandshakeSecret: ServerHandshakeSecret,
	}

	return schedule
}

// ApplicationSecrets derives the client and server application traffic
// secrets from the transcript through the server Finished.
func (s *Schedule) ApplicationSecrets(transcript []byte) (clientSecret, serverSecret []byte) {
	newHash := hashFunc(s.HashName)

	clientSecret = deriveSecret(newHash, s.HashName, s.MasterSecret, "c ap traffic", transcript)
	serverSecret = deriveSecret(newHash, s.HashName, s.MasterSecret, "s ap traffic", transcript)

	return clientSecret, serverSecret
}

// TrafficKey derives the key and IV for a traffic secret.
func (s *Schedule) TrafficKey(secret []byte, suite *hqgotlsciphers.Suite) (key, iv []byte, err error) {
	var keyLen int

	switch suite.Encryption {
	case "AES128-GCM":
		keyLen = 16
	case "AES256-GCM":
		keyLen = 32
	case "CHACHA20-POLY1305":
		keyLen = 32
	default:
		return nil, nil, hqgoerrors.Errorf("%w: %s", ErrUnsupportedCipherSuite, suite.Name)
	}

	newHash := hashFunc(s.HashName)

	key = hkdfExpandLabel(newHash, secret, "key", nil, keyLen)
	iv = hkdfExpandLabel(newHash, secret, "iv", nil, 12)

	return key, iv, nil
}

// FinishedKey derives the Finished key for a traffic secret.
func (s *Schedule) FinishedKey(secret []byte) (key []byte) {
	newHash := hashFunc(s.HashName)

	return hkdfExpandLabel(newHash, secret, "finished", nil, s.HashLen)
}

// TLS13FinishedVerify computes Finished verify_data.
func TLS13FinishedVerify(FinishedKey, transcript []byte, HashName string) (verifyData []byte) {
	mac := hmac.New(hashFunc(HashName), FinishedKey)
	mac.Write(transcriptHash(HashName, transcript))

	return mac.Sum(nil)
}

// hkdfExtract implements HKDF-Extract.
func hkdfExtract(newHash func() hash.Hash, salt, ikm []byte) (prk []byte) {
	mac := hmac.New(newHash, salt)
	mac.Write(ikm)

	return mac.Sum(nil)
}

// deriveSecret implements Derive-Secret from RFC 8446.
func deriveSecret(newHash func() hash.Hash, HashName string, secret []byte, label string, transcript []byte) (derived []byte) {
	HashLen := 32
	if HashName == "SHA384" {
		HashLen = 48
	}

	return hkdfExpandLabel(newHash, secret, label, transcriptHash(HashName, transcript), HashLen)
}
