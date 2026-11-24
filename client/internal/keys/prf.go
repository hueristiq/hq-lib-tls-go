package keys

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // G501: TLS 1.0/SSL 3.0 require MD5.
	"crypto/sha1" //nolint:gosec // G505: TLS 1.0/SSL 3.0 require SHA-1.
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strings"

	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

// prf computes the protocol PRF for the given version and suite hash.
func prf(version uint16, hashName string, secret []byte, label string, seed []byte, length int) (out []byte) {
	switch {
	case version >= hqgotlsciphers.VersionTLS12:
		return prf12(hashFunc(hashName), secret, label, seed, length)
	case version == hqgotlsciphers.VersionSSL30:
		return ssl3PRF(secret, append([]byte(label), seed...), length)
	default:
		return prf10(secret, label, seed, length)
	}
}

// prf12 implements the TLS 1.2 PRF.
func prf12(newHash func() hash.Hash, secret []byte, label string, seed []byte, length int) (out []byte) {
	labelAndSeed := make([]byte, 0, len(label)+len(seed))
	labelAndSeed = append(labelAndSeed, label...)
	labelAndSeed = append(labelAndSeed, seed...)

	return pHash(newHash, secret, labelAndSeed, length)
}

// prf10 implements the TLS 1.0/1.1 PRF.
func prf10(secret []byte, label string, seed []byte, length int) (out []byte) {
	labelAndSeed := make([]byte, 0, len(label)+len(seed))
	labelAndSeed = append(labelAndSeed, label...)
	labelAndSeed = append(labelAndSeed, seed...)

	s1, s2 := splitPreMasterSecret(secret)

	md5Part := pHash(md5.New, s1, labelAndSeed, length)
	sha1Part := pHash(sha1.New, s2, labelAndSeed, length)

	out = make([]byte, length)
	for i := range out {
		out[i] = md5Part[i] ^ sha1Part[i]
	}

	return out
}

// pHash implements the P_hash expansion.
func pHash(newHash func() hash.Hash, secret, seed []byte, length int) (out []byte) {
	out = make([]byte, 0, length)

	a := seed

	for len(out) < length {
		a = hmacSum(newHash, secret, a)
		out = append(out, hmacSum(newHash, secret, append(append([]byte(nil), a...), seed...))...)
	}

	return out[:length]
}

// hmacSum returns HMAC(newHash, key, data).
func hmacSum(newHash func() hash.Hash, key, data []byte) (sum []byte) {
	mac := hmac.New(newHash, key)
	mac.Write(data)

	return mac.Sum(nil)
}

// splitPreMasterSecret splits secret into two halves for the TLS 1.0 PRF.
func splitPreMasterSecret(secret []byte) (s1, s2 []byte) {
	s1 = secret[:len(secret)/2+len(secret)%2]
	s2 = secret[len(secret)/2+len(secret)%2:]

	return s1, s2
}

// ssl3PRF implements the SSL 3.0 PRF: repeated MD5(secret + SHA1(salt +
// secret + seed)).
func ssl3PRF(secret, seed []byte, length int) (out []byte) {
	out = make([]byte, 0, length+16)

	for i := 1; len(out) < length; i++ {
		salt := make([]byte, i)

		for j := range salt {
			salt[j] = byte('A' + i - 1)
		}

		inner := make([]byte, 0, len(salt)+len(secret)+len(seed))
		inner = append(inner, salt...)
		inner = append(inner, secret...)
		inner = append(inner, seed...)

		sha := sha1.Sum(inner) //nolint:gosec // G401: SSL 3.0 protocol requirement.

		outer := make([]byte, 0, len(secret)+len(sha))
		outer = append(outer, secret...)
		outer = append(outer, sha[:]...)

		sum := md5.Sum(outer) //nolint:gosec // G401: SSL 3.0 protocol requirement.

		out = append(out, sum[:]...)
	}

	return out[:length]
}

// exportPRF30 implements the SSL 3.0 export PRF: MD5(secret + seed),
// truncated to length.
func exportPRF30(secret, seed []byte, length int) (out []byte) {
	material := make([]byte, 0, len(secret)+len(seed))
	material = append(material, secret...)
	material = append(material, seed...)

	sum := md5.Sum(material) //nolint:gosec // G401: SSL 3.0 export protocol requirement.

	out = make([]byte, length)

	copy(out, sum[:])

	return out
}

// hkdfExpandLabel implements HKDF-Expand-Label from RFC 8446.
func hkdfExpandLabel(newHash func() hash.Hash, secret []byte, label string, context []byte, length int) (out []byte) {
	fullLabel := "tls13 " + label

	info := make([]byte, 0, 4+len(fullLabel)+len(context))
	info = append(info, byte(length>>8), byte(length), byte(len(fullLabel))) //nolint:gosec // G115: RFC 8446 lengths are bounded by the hash size.
	info = append(info, fullLabel...)
	info = append(info, byte(len(context))) //nolint:gosec // G115: RFC 8446 lengths are bounded by the hash size.
	info = append(info, context...)

	out, _ = hkdf.Expand(newHash, secret, string(info), length)

	return out
}

// transcriptHash computes the handshake transcript hash for a TLS 1.2/1.3
// hash name.
func transcriptHash(hashName string, messages []byte) (sum []byte) {
	switch hashName {
	case "SHA384":
		digest := sha512.Sum384(messages)

		return digest[:]
	default:
		digest := sha256.Sum256(messages)

		return digest[:]
	}
}

// transcriptMD5SHA1 computes the TLS 1.0/1.1 Finished hash.
func transcriptMD5SHA1(messages []byte) (sum []byte) {
	md5Digest := md5.Sum(messages)   //nolint:gosec // G401: TLS 1.0/1.1 protocol requirement.
	sha1Digest := sha1.Sum(messages) //nolint:gosec // G401: TLS 1.0/1.1 protocol requirement.

	sum = make([]byte, 0, len(md5Digest)+len(sha1Digest))
	sum = append(sum, md5Digest[:]...)
	sum = append(sum, sha1Digest[:]...)

	return sum
}

// hashNameForSuite returns the hash name for a suite.
func hashNameForSuite(name string) (hashName string) {
	if name == "" {
		return "SHA256"
	}

	upper := strings.ToUpper(name)

	switch {
	case strings.Contains(upper, "384"):
		return "SHA384"
	case strings.Contains(upper, "256"):
		return "SHA256"
	case strings.Contains(upper, "SHA1"), strings.Contains(upper, "SHA"):
		return "SHA1"
	case strings.Contains(upper, "MD5"):
		return "MD5"
	default:
		return "SHA256"
	}
}

// hashFunc returns the hash constructor for a suite hash name.
func hashFunc(name string) (newHash func() hash.Hash) {
	switch name {
	case "MD5":
		newHash = md5.New
	case "SHA1", "SHA":
		newHash = sha1.New
	case "SHA256":
		newHash = sha256.New
	case "SHA384":
		newHash = sha512.New384
	default:
		newHash = sha256.New
	}

	return newHash
}

// macLength returns the MAC length for a suite hash name.
func macLength(name string) (size int) {
	switch name {
	case "MD5":
		size = 16
	case "SHA1", "SHA":
		size = 20
	case "SHA256":
		size = 32
	case "SHA384":
		size = 48
	default:
		size = 32
	}

	return size
}

// PRF computes the protocol PRF for the given version and suite hash.
func PRF(version uint16, hashName string, secret []byte, label string, seed []byte, length int) (out []byte) {
	return prf(version, hashName, secret, label, seed, length)
}

// PRF10 implements the TLS 1.0/1.1 PRF.
func PRF10(secret []byte, label string, seed []byte, length int) (out []byte) {
	return prf10(secret, label, seed, length)
}

// PRF12 implements the TLS 1.2 PRF.
func PRF12(newHash func() hash.Hash, secret []byte, label string, seed []byte, length int) (out []byte) {
	return prf12(newHash, secret, label, seed, length)
}

// HashFunc returns the hash constructor for a suite hash name.
func HashFunc(name string) (newHash func() hash.Hash) {
	return hashFunc(name)
}

// MACLength returns the MAC length for a suite hash name.
func MACLength(name string) (size int) {
	return macLength(name)
}

// TranscriptHash computes the handshake transcript hash.
func TranscriptHash(hashName string, messages []byte) (sum []byte) {
	return transcriptHash(hashName, messages)
}

// HashNameForSuite returns the hash name for a suite.
func HashNameForSuite(name string) (hashName string) {
	return hashNameForSuite(name)
}

// md5Sum returns the MD5 digest of data.
func md5Sum(data []byte) (sum []byte) {
	digest := md5.Sum(data) //nolint:gosec // G401: SSL 3.0 Finished requires MD5.

	return digest[:]
}
