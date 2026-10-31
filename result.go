package tls

// Result is the outcome of inspecting one host, filled identically by every
// connection mode. Certificates and handshake messages cross the package
// boundary as raw bytes, so no mode-specific types leak to callers.
//
// Fields:
//   - Host (string): the host inspected, as given (hostname or IP, without port).
//   - IP (string): the IP address the connection used; empty when the
//     connection never reached a peer.
//   - Mode (Mode): the mode that produced the result; after an [ModeAuto]
//     fallback this is the mode that actually succeeded.
//   - TLSVersion (uint16): the negotiated TLS version; zero when no
//     handshake completed.
//   - CipherSuite (uint16): the negotiated cipher suite; zero when no
//     handshake completed.
//   - ALPN (string): the negotiated application protocol, if any.
//   - Certificates ([][]byte): the DER-encoded certificate chain, leaf
//     first; empty when the server offered none.
//   - ClientHello ([]byte): the raw ClientHello message the client sent;
//     captured in [ModeZTLS] and [ModeAuto] (when zcrypto ran) only.
//   - ServerHello ([]byte): the raw ServerHello message the server sent;
//     captured in [ModeZTLS] and [ModeAuto] (when zcrypto ran) only.
//   - Error (error): the handshake failure, if the server was reached but
//     the handshake did not complete.
type Result struct {
	Host         string
	IP           string
	Mode         Mode
	TLSVersion   uint16
	CipherSuite  uint16
	ALPN         string
	Certificates [][]byte
	ClientHello  []byte
	ServerHello  []byte
	Error        error
}
