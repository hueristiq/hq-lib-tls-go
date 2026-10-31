package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJoinUint8sSkipsGrease(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "0-2", joinUint8s([]byte{0x0a, 0x00, 0x1a, 0x02}))
}
