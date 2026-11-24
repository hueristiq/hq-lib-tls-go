package certificate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpired(t *testing.T) {
	t.Parallel()

	_, _, leafCertificate := testCA(t, []string{"example.com"})

	leaf, err := Parse([][]byte{leafCertificate.Raw})

	require.NoError(t, err)

	assert.False(t, leaf[0].Expired(time.Now()))
	assert.False(t, leaf[0].Expired(leaf[0].NotBefore))
	assert.True(t, leaf[0].Expired(leaf[0].NotAfter.Add(time.Second)))
	assert.False(t, (*Cert)(nil).Expired(time.Now()))
}

func TestSelfSigned(t *testing.T) {
	t.Parallel()

	caCertificate, _, leafCertificate := testCA(t, []string{"example.com"})

	chain, err := Parse([][]byte{leafCertificate.Raw, caCertificate.Raw})

	require.NoError(t, err)

	assert.False(t, chain[0].SelfSigned())
	assert.True(t, chain[1].SelfSigned())
}

func TestMismatched(t *testing.T) {
	t.Parallel()

	_, _, leafCertificate := testCA(t, []string{"example.com"})

	leaf, err := Parse([][]byte{leafCertificate.Raw})

	require.NoError(t, err)

	assert.False(t, leaf[0].Mismatched("example.com"))
	assert.True(t, leaf[0].Mismatched("other.org"))
}

func TestSelfSignedNilReceiver(t *testing.T) {
	t.Parallel()

	assert.False(t, (*Cert)(nil).SelfSigned())
}
