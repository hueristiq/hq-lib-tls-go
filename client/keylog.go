package client

import "fmt"

// logTrafficSecret writes a TLS 1.3 traffic secret to KeyLogWriter.
func (c *Conn) logTrafficSecret(label string, clientRandom, secret []byte) {
	if c.config == nil || c.config.KeyLogWriter == nil {
		return
	}

	_, _ = fmt.Fprintf(c.config.KeyLogWriter, "%s %x %x\n", label, clientRandom, secret)
}

// logMasterSecret writes the TLS 1.2 master secret to KeyLogWriter.
func (c *Conn) logMasterSecret(clientRandom, master []byte) {
	if c.config == nil || c.config.KeyLogWriter == nil {
		return
	}

	_, _ = fmt.Fprintf(c.config.KeyLogWriter, "CLIENT_RANDOM %x %x\n", clientRandom, master)
}
