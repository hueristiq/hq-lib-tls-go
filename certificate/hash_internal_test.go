package certificate

import (
	"crypto/md5"  //nolint:gosec // G501: the test verifies the package's MD5 digest.
	"crypto/sha1" //nolint:gosec // G505: the test verifies the package's SHA-1 digest.
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashes(t *testing.T) {
	t.Parallel()

	_, _, leafCertificate := testCA(t, []string{"example.com"})

	leaf, err := Parse([][]byte{leafCertificate.Raw})

	require.NoError(t, err)

	certificate := leaf[0]

	md5Sum := md5.Sum(leafCertificate.Raw)   //nolint:gosec // G401: the test verifies the package's MD5 digest.
	sha1Sum := sha1.Sum(leafCertificate.Raw) //nolint:gosec // G401: the test verifies the package's SHA-1 digest.
	sha256Sum := sha256.Sum256(leafCertificate.Raw)

	assert.Equal(t, hex.EncodeToString(md5Sum[:]), certificate.MD5())
	assert.Equal(t, hex.EncodeToString(sha1Sum[:]), certificate.SHA1())
	assert.Equal(t, hex.EncodeToString(sha256Sum[:]), certificate.SHA256())
}
