// Package probe connects to TLS servers and captures what they offer:
// negotiated protocol parameters, certificates, and raw handshake messages.
//
// A [Prober] performs a single connection per target and produces one
// [Result] that all analysis builds on. The connection itself runs in one of
// four modes:
//
//   - [ModeAuto] — try zcrypto first, fall back to stdlib crypto/tls on
//     failure (the default).
//   - [ModeZTLS] — dial through zmap/zcrypto, which tolerates older and
//     malformed servers and captures the raw ClientHello and ServerHello
//     messages, enabling JA3/JA3S fingerprints.
//   - [ModeCTLS] — dial through the Go standard library's crypto/tls; the
//     most interoperable option, without raw handshake capture.
//   - [ModeOpenSSL] — shell out to the OpenSSL binary (s_client) and parse
//     its session output; requires openssl on PATH unless
//     [WithOpenSSLBinary] points elsewhere.
//
// [Prober.JARM] computes a JARM fingerprint: it sends the ten crafted
// ClientHello probes defined by the JARM specification over raw TCP and
// fuzzy-hashes the server's responses, without completing any handshake.
//
// The results carry no third-party types: certificates and handshake
// messages cross the package boundary as raw bytes, so every mode fills the
// same [Result] shape regardless of the dialing library underneath.
package probe
