// Package authority generates, manages, and signs X.509 certificates for
// building TLS servers with dynamic, per-host certificate issuance.
//
// # Entry points
//
// The package offers two complementary capabilities:
//
//   - One-off generation. [GenerateCACertificatePrivateKey] produces a
//     self-signed Certificate Authority (CA);
//     [GenerateCACertificatePrivateKeyPEM] returns the same pair PEM-encoded.
//     PEM helpers ([CertificateToPEM], [PrivateKeyToPEM]) and file helpers
//     ([SaveCertificatePrivateKeyToFiles],
//     [LoadCertificatePrivateKeyFromFiles]) move certificates to and from
//     disk.
//   - A long-lived signing authority. [CertificateAuthority], constructed with
//     [New] or [NewFromPEM], issues leaf certificates on demand through
//     [CertificateAuthority.GenerateTLSCertificate] and signs certificate
//     signing requests through [CertificateAuthority.SignCSR].
//     [CertificateAuthority.NewTLSConfig] returns a [crypto/tls.Config] whose
//     GetCertificate hook mints a certificate for the hostname a client
//     requests via Server Name Indication (SNI);
//     [CertificateAuthority.TLSCertificate] returns the same bundled
//     *tls.Certificate (leaf plus CA chain) for a host programmatically. This
//     suits TLS-intercepting proxies and multi-tenant servers that cannot
//     enumerate their hostnames in advance.
//
// # Configuration
//
// Four functional option families configure the package:
//
//   - [CAOption] over [CAOptions] configures CA generation: subject, validity,
//     and key algorithm. [WithCACommonName] is required; the validity defaults
//     to 365 days and the key to [KeyTypeRSA2048].
//   - [IssueOption] over [IssueOptions] configures leaf issuance and CSR signing:
//     subject, validity, and extended key usages. The validity defaults to 365
//     days and is clamped to the CA's expiry.
//   - [TLSConfigMutator] configures the [crypto/tls.Config] returned by
//     [CertificateAuthority.NewTLSConfig] and
//     [CertificateAuthority.NewTLSConfigWithHost]; [WithNextProtos] and
//     [WithAllowedHosts] cover ALPN and SNI allowlisting.
//   - [Option] over [Options] configures the authority itself: the optional
//     certificate cache ([WithCache]) and its maximum age
//     ([WithCacheMaxAge], one hour by default).
//
// Nil options are ignored, and because the parameter types are exported,
// callers can write custom options. Invalid values make the constructors
// return an error.
//
// # Production use
//
// The certificate cache is off by default: an authority created without
// [WithCache] regenerates a certificate on every request. Enable caching with
// [WithCache], passing a cache sized to the number of distinct hosts served
// ([cache.NewInMemory] is the ready-made implementation), and
// set [WithCacheMaxAge] well below the leaf validity. For dynamic per-host
// issuance, consider [WithCAKeyType] with [KeyTypeECDSAP256]: ECDSA-P256 leaf
// generation is markedly faster than RSA-2048.
//
// # Key algorithms
//
// RSA-2048, ECDSA (NIST P-256), and Ed25519 are supported through the
// [crypto.Signer] interface. Select the CA's algorithm with
// [WithCAKeyType]. Every leaf certificate inherits the
// CA's algorithm, so an ECDSA or Ed25519 CA yields markedly faster per-host
// issuance than RSA.
//
// # Basic usage
//
// Generate a CA, wrap it in an authority, and serve TLS with SNI-driven
// certificates:
//
//	caCert, caKey, err := hqgotlsauthority.GenerateCACertificatePrivateKey(
//		hqgotlsauthority.WithCACommonName("Example Root CA"),
//		hqgotlsauthority.WithCAKeyType(hqgotlsauthority.KeyTypeECDSAP256),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	authority, err := hqgotlsauthority.New(caCert, caKey)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	server := &http.Server{
//		Addr:      ":443",
//		TLSConfig: authority.NewTLSConfig(),
//	}
//
//	log.Fatal(server.ListenAndServeTLS("", ""))
//
// Clients must trust the generated CA certificate (for example by adding it to
// their root pool) for the handshake to succeed.
//
// # Standards and safety
//
// Certificates follow RFC 5280 — random 128-bit serial numbers and SHA-256
// subject key identifiers — and are PEM-encoded per RFC 7468. Leaf certificates
// are clamped to the CA's expiry so they never outlive their issuer, and
// issuance fails when the requested validity starts at or after the CA's
// expiry. TLS configs
// produced by the authority require TLS 1.2 or higher and, by default, advertise
// the HTTP/2 and HTTP/1.1 ALPN protocols (overridable with
// [WithNextProtos]).
//
// # Concurrency
//
// A [CertificateAuthority] is safe for concurrent use by multiple goroutines.
// Concurrent requests for the same hostname share a single in-flight
// generation, so a burst of handshakes does not multiply key-generation work.
//
// # Client side
//
// Probing remote TLS servers — dialing, fingerprinting, and certificate
// analysis — lives in the root package, [fingerprint], and [certificate],
// not here.
//
// [cache.NewInMemory]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/authority/cache#NewInMemory
// [fingerprint]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/fingerprint
// [certificate]: https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go/certificate
package authority
