package cert

import (
	"crypto/md5"  //nolint:gosec // G501: certificate fingerprint digests are the package's purpose.
	"crypto/sha1" //nolint:gosec // G505: certificate fingerprint digests are the package's purpose.
	"crypto/sha256"
	"encoding/hex"
)

// MD5 returns the MD5 digest of the certificate's DER encoding, in
// lowercase hexadecimal.
//
// Returns:
//   - hash (string): the digest.
func (c *Certificate) MD5() (hash string) {
	sum := md5.Sum(c.Raw) //nolint:gosec // G401: the MD5 fingerprint is explicitly requested.

	return hex.EncodeToString(sum[:])
}

// SHA1 returns the SHA-1 digest of the certificate's DER encoding, in
// lowercase hexadecimal.
//
// Returns:
//   - hash (string): the digest.
func (c *Certificate) SHA1() (hash string) {
	sum := sha1.Sum(c.Raw) //nolint:gosec // G401: the SHA-1 fingerprint is explicitly requested.

	return hex.EncodeToString(sum[:])
}

// SHA256 returns the SHA-256 digest of the certificate's DER encoding, in
// lowercase hexadecimal.
//
// Returns:
//   - hash (string): the digest.
func (c *Certificate) SHA256() (hash string) {
	sum := sha256.Sum256(c.Raw)

	return hex.EncodeToString(sum[:])
}
