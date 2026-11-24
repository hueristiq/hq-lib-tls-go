package tls

import (
	hqgotlscertificate "github.com/hueristiq/hq-lib-tls-go/certificate"
	hqgotlsclient "github.com/hueristiq/hq-lib-tls-go/client"
)

// Result is the outcome of inspecting one host.
//
// Fields:
//   - Host (string): the host inspected, as given (hostname or IP, without
//     port).
//   - IP (string): the IP address the connection used; empty when the
//     connection never reached a peer.
//   - TLSVersion (uint16): the negotiated TLS version; zero when no handshake
//     completed.
//   - CipherSuite (uint16): the negotiated cipher suite; zero when no
//     handshake completed.
//   - ALPN (string): the negotiated application protocol, if any.
//   - Certificates ([][]byte): the DER-encoded certificate chain, leaf first.
//   - CertificateReport (*certificate.Report): parsed certificate metadata;
//     nil when no chain was offered or parsing failed.
//   - ExportCipher (bool): whether the negotiated suite is export-grade.
//   - Handshake (*client.HandshakeLog): the decrypted handshake trace.
//   - Trace ([]client.HandshakeEvent): the same trace as a slice.
type Result struct {
	Host              string
	IP                string
	TLSVersion        uint16
	CipherSuite       uint16
	ALPN              string
	Certificates      [][]byte
	CertificateReport *hqgotlscertificate.Report
	ExportCipher      bool
	Handshake         *hqgotlsclient.HandshakeLog
	Trace             []hqgotlsclient.HandshakeEvent
}
