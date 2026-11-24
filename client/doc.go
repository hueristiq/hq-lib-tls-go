// Package client is a native client TLS implementation with a
// crypto/tls-familiar API. It speaks SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, and
// TLS 1.3, including export-grade cipher suites, and exposes every decrypted
// handshake message.
//
// # Entry points
//
// [Dial], [DialContext], [DialTimeout], [DialWithDialer], and
// [DialWithDialerContext] connect and complete a handshake. [NewConn] wraps an
// existing [net.Conn]; [Conn.Handshake] and [Conn.HandshakeContext] run the
// handshake lazily. [Conn.ConnectionState] reports the negotiated version,
// cipher suite, ALPN protocol, and peer certificates.
//
// # Configuration
//
// [Config] mirrors crypto/tls fields — ServerName, InsecureSkipVerify,
// RootCAs, Certificates, NextProtos, CipherSuites, MinVersion, MaxVersion,
// CurvePreferences, and verification hooks — and adds probing controls:
//
//   - AllowExportCipherSuites permits export-grade suites.
//
//   - HelloSpec supplies an exact ClientHello.
//
//   - HandshakeLogger receives every decrypted handshake message.
//
//   - RecordFragmentation splits handshake writes across records.
//
// # Legacy protocols
//
// Setting MinVersion to [VersionSSL30], [VersionTLS10], or [VersionTLS11]
// enables the legacy record and handshake rules, including implicit CBC IVs,
// SSL 3.0 MACs, and export key expansion. Export suites are rejected unless
// AllowExportCipherSuites is set.
//
// # Handshake logging
//
// [Conn.HandshakeTrace] and [Conn.HandshakeLog] return the messages observed
// during the handshake. Because the engine owns the key schedule, the trace
// contains plaintext bodies for every message, including TLS 1.3's encrypted
// handshake flight. [Config.HandshakeLogger] streams the same events as they
// occur.
//
// # Security
//
// This package is designed for protocol inspection and interoperability
// testing, including against deliberately broken servers. It deliberately
// supports algorithms that are unsafe for protecting real traffic (SSL 3.0,
// RC4, DES, export ciphers). Do not use it as a general-purpose secure
// transport; use crypto/tls for that.
//
// # Concurrency
//
// A [Conn] supports one concurrent reader and one concurrent writer after the
// handshake, matching net.Conn's contract. A [Config] must not be modified
// while a connection is using it; use [Config.Clone] to derive variants.
package client
