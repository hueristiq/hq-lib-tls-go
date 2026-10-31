package fingerprint

import (
	"crypto/md5" //nolint:gosec // G501: the digest under test is defined as an MD5 hash.
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDigest(t *testing.T) {
	t.Parallel()

	const segment = "771,49199,43"

	sum := md5.Sum([]byte(segment)) //nolint:gosec // G401: the digest under test is defined as an MD5 hash.

	assert.Equal(t, hex.EncodeToString(sum[:]), Digest(segment))
}
