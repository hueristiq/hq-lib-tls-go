package keys

import (
	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// ErrUnsupportedCipherSuite reports a cipher suite the key derivation
// package cannot handle.
const ErrUnsupportedCipherSuite hqgoerrors.Sentinel = "unsupported cipher suite"
