package certificate

import (
	"bytes"
	"time"
)

// Expired reports whether the certificate's validity period has already
// ended at now.
func (c *Cert) Expired(now time.Time) (expired bool) {
	if c == nil {
		return false
	}

	return !now.Before(c.NotAfter)
}

// SelfSigned reports whether the certificate's subject is its own issuer:
// its subject and issuer names are byte-identical.
func (c *Cert) SelfSigned() (selfSigned bool) {
	if c == nil {
		return false
	}

	return bytes.Equal(c.RawSubject, c.RawIssuer)
}

// Mismatched reports whether the certificate does not cover host.
func (c *Cert) Mismatched(host string) (mismatched bool) {
	return !c.CoversHost(host)
}
