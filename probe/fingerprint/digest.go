package fingerprint

import (
	"crypto/md5" //nolint:gosec // G501: the JA3 digest is defined as an MD5 hash.
	"encoding/hex"
)

// Digest reduces a fingerprint segment to its canonical MD5 hash — the
// form JA3 and JA3S fingerprints are usually compared and shared in.
//
// Parameters:
//   - segment (string): the fingerprint segment.
//
// Returns:
//   - digest (string): the lowercase hexadecimal MD5 digest.
func Digest(segment string) (digest string) {
	sum := md5.Sum([]byte(segment)) //nolint:gosec // G401: the JA3 digest is defined as an MD5 hash.

	return hex.EncodeToString(sum[:])
}
