# hq-lib-tls-go

![made with go](https://img.shields.io/badge/made%20with-Go-1E90FF.svg) [![go reference](https://pkg.go.dev/badge/github.com/hueristiq/hq-lib-tls-go.svg)](https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go) [![license](https://img.shields.io/badge/license-MIT-gray.svg?color=1E90FF)](https://github.com/hueristiq/hq-lib-tls-go/blob/main/LICENSE) ![maintenance](https://img.shields.io/badge/maintained%3F-yes-1E90FF.svg) [![open issues](https://img.shields.io/github/issues-raw/hueristiq/hq-lib-tls-go.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-lib-tls-go/issues?q=is:issue+is:open) [![closed issues](https://img.shields.io/github/issues-closed-raw/hueristiq/hq-lib-tls-go.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-lib-tls-go/issues?q=is:issue+is:closed) [![contribution](https://img.shields.io/badge/contributions-welcome-1E90FF.svg)](https://github.com/hueristiq/hq-lib-tls-go/blob/main/CONTRIBUTING.md)

`hq-lib-tls-go` is a [Go](https://golang.org/) package for serving and probing TLS: generating, managing, and signing X.509 certificates on the server side, and connecting to, fingerprinting, and analyzing remote TLS servers on the client side.

## Resources

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
	- [Serving: Generating a CA Certificate](#serving-generating-a-ca-certificate)
	- [Serving: Choosing the Key Algorithm](#serving-choosing-the-key-algorithm)
	- [Serving: Loading a Certificate from Files](#serving-loading-a-certificate-from-files)
	- [Serving: Loading a CA from PEM Bytes](#serving-loading-a-ca-from-pem-bytes)
	- [Serving: Generating a TLS Certificate](#serving-generating-a-tls-certificate)
	- [Serving: Signing a Certificate Signing Request (CSR)](#serving-signing-a-certificate-signing-request-csr)
	- [Serving: Configuring a TLS Server with SNI](#serving-configuring-a-tls-server-with-sni)
	- [Serving: Restricting Issuance to Known Hosts](#serving-restricting-issuance-to-known-hosts)
	- [Probing: Connecting to a TLS Server](#probing-connecting-to-a-tls-server)
	- [Probing: Computing JA3/JA3S Fingerprints](#probing-computing-ja3ja3s-fingerprints)
	- [Probing: Computing the JARM Fingerprint](#probing-computing-the-jarm-fingerprint)
	- [Probing: Analyzing Certificates](#probing-analyzing-certificates)
- [Contributing](#contributing)
- [Licensing](#licensing)

## Features

- **Serving — Self-Signed CA Generation:** Create CA certificates with custom subject, validity, and key algorithm (RSA-2048, ECDSA P-256, or Ed25519).
- **Serving — TLS Certificate Issuance:** Issue leaf certificates for DNS names, IPs, emails, or URIs, with keys inheriting the CA's algorithm.
- **Serving — Dynamic TLS Configuration:** SNI-driven per-host certificate generation, TLS 1.2 minimum, HTTP/2 and HTTP/1.1 ALPN.
- **Serving — Opt-In Certificate Caching:** Pluggable caching via the `cache` package; without it, certificates are regenerated per request.
- **Serving — SNI Allowlist:** Restrict dynamic issuance to known hostnames with `WithAllowedHosts`, bounding CPU use on Internet-facing servers.
- **Probing — Configurable Connection Modes:** Dial through stdlib `crypto/tls` (`ctls`), zmap/zcrypto with raw handshake capture (`ztls`), the OpenSSL binary (`openssl`), or `auto`, which tries zcrypto first and falls back to the standard library.
- **Probing — Early Termination:** Pre-handshake mode captures the ServerHello and certificates without completing the key exchange, for fast certificate gathering.
- **Probing — Fingerprints:** JA3 and JA3S segments from captured handshake messages, and the JARM fingerprint via its ten crafted ClientHello probes.
- **Probing — Certificate Analysis:** Tolerant chain parsing, subject/issuer metadata, hostname coverage, digests, and trust/revocation checks.
- **Probing — Cipher Classification:** An embedded cipher-suite security table (insecure/weak/secure/recommended), generated from the ciphersuite.info dataset.

## Installation

To install `hq-lib-tls-go`, run the following command in your Go project:

```bash
go get -v -u github.com/hueristiq/hq-lib-tls-go
```

## Usage

The serving API lives in the `authority` subpackage; the probing API lives in `probe`, `probe/fingerprint`, and `cert`. The examples below import them under the `hqgotlsauthority`, `hqgotlsprobe`, `hqgotlsfingerprint`, and `hqgotlscert` aliases.

### Serving: Generating a CA Certificate

Use `GenerateCACertificatePrivateKey` to create a self-signed CA certificate and its private key. By default it generates a 2048-bit RSA key; see [Choosing the Key Algorithm](#serving-choosing-the-key-algorithm) to select ECDSA or Ed25519. Persist the result to PEM files with `SaveCertificatePrivateKeyToFiles`.

```go
package main

import (
	"log"
	"time"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
)

func main() {
	// Generate a CA certificate with custom options.
	caCert, caKey, err := hqgotlsauthority.GenerateCACertificatePrivateKey(
		hqgotlsauthority.WithCACommonName("My Root CA"),
		hqgotlsauthority.WithCAOrganization([]string{"My Company"}),
		hqgotlsauthority.WithCAValidFor(365*24*time.Hour),
	)
	if err != nil {
		log.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Save to PEM files.
	if err = hqgotlsauthority.SaveCertificatePrivateKeyToFiles(caCert, caKey, "ca-cert.pem", "ca-key.pem"); err != nil {
		log.Fatalf("Failed to save CA certificate: %v", err)
	}

	log.Println("CA certificate and key saved to ca-cert.pem and ca-key.pem")
}
```

### Serving: Choosing the Key Algorithm

Pass `WithCAKeyType` to control the CA's private key algorithm. Because every leaf certificate inherits the CA's algorithm, an ECDSA or Ed25519 CA also makes per-host issuance faster — useful for the SNI server below, which generates a key per hostname.

```go
caCert, caKey, err := hqgotlsauthority.GenerateCACertificatePrivateKey(
	hqgotlsauthority.WithCACommonName("My Root CA"),
	hqgotlsauthority.WithCAKeyType(hqgotlsauthority.KeyTypeECDSAP256),
)
```

Available key types: `KeyTypeRSA2048` (default), `KeyTypeECDSAP256`, and `KeyTypeEd25519`.

### Serving: Loading a Certificate from Files

Load a certificate and private key from PEM files with `LoadCertificatePrivateKeyFromFiles`.

```go
package main

import (
	"log"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
)

func main() {
	caCert, caKey, err := hqgotlsauthority.LoadCertificatePrivateKeyFromFiles("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}

	log.Printf("Loaded CA certificate %q with key type %T\n", caCert.Subject.CommonName, caKey)
}
```

### Serving: Loading a CA from PEM Bytes

When the certificate and key are already in memory (for example, read from a secret store), construct the authority directly with `NewFromPEM`.

```go
ca, err := hqgotlsauthority.NewFromPEM(caCertPEM, caKeyPEM)
if err != nil {
	log.Fatalf("Failed to initialize CA: %v", err)
}
```

### Serving: Generating a TLS Certificate

Use a `CertificateAuthority` to issue a leaf certificate for specific hosts. Each host is routed into the matching Subject Alternative Name field — DNS name, IP address, email address, or URI.

```go
package main

import (
	"log"
	"time"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
)

func main() {
	// Load CA certificate and private key.
	caCert, caKey, err := hqgotlsauthority.LoadCertificatePrivateKeyFromFiles("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}

	// Initialize the CertificateAuthority.
	ca, err := hqgotlsauthority.New(caCert, caKey)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Generate a TLS certificate for multiple hosts.
	tlsCert, tlsKey, err := ca.GenerateTLSCertificate(
		[]string{"example.com", "www.example.com", "192.168.1.1", "user@example.com"},
		hqgotlsauthority.WithTLSCommonName("example.com"),
		hqgotlsauthority.WithTLSOrganization([]string{"My Company"}),
		hqgotlsauthority.WithTLSValidFor(30*24*time.Hour), // 30 days
	)
	if err != nil {
		log.Fatalf("Failed to generate TLS certificate: %v", err)
	}

	// Save the TLS certificate and key.
	if err := hqgotlsauthority.SaveCertificatePrivateKeyToFiles(tlsCert, tlsKey, "tls-cert.pem", "tls-key.pem"); err != nil {
		log.Fatalf("Failed to save TLS certificate: %v", err)
	}

	log.Println("TLS certificate and key saved to tls-cert.pem and tls-key.pem")
}
```

By default the extended key usage is derived from the SAN kinds present: server authentication when the certificate names a host (DNS name, IP address, or URI) and email protection when it names an email address. To issue a client certificate for mutual TLS, set the extended key usage explicitly:

```go
clientCert, clientKey, err := ca.GenerateTLSCertificate(
	[]string{"client.example.com"},
	hqgotlsauthority.WithTLSExtKeyUsage(x509.ExtKeyUsageClientAuth),
)
```

### Serving: Signing a Certificate Signing Request (CSR)

`SignCSR` signs a CSR with the CA's private key: the client keeps its private key, and the CA never sees it. The CSR's signature is verified before signing, its subject alternative names are copied to the certificate, and the default extended key usage is client authentication — suited to issuing client certificates for mutual TLS. The same `TLSOption`s as `GenerateTLSCertificate` override the defaults.

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
)

func main() {
	// Load CA certificate and private key.
	caCert, caKey, err := hqgotlsauthority.LoadCertificatePrivateKeyFromFiles("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}

	// Initialize the CertificateAuthority.
	ca, err := hqgotlsauthority.New(caCert, caKey)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Client side: build a CSR (in practice it arrives from the client).
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate client key: %v", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "client.example.com"},
		DNSNames: []string{"client.example.com"},
	}, clientKey)
	if err != nil {
		log.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		log.Fatalf("Failed to parse CSR: %v", err)
	}

	// CA side: sign the CSR.
	clientCert, err := ca.SignCSR(csr)
	if err != nil {
		log.Fatalf("Failed to sign CSR: %v", err)
	}

	log.Printf("Issued client certificate %q, valid until %v\n", clientCert.Subject.CommonName, clientCert.NotAfter)
}
```

### Serving: Configuring a TLS Server with SNI

`NewTLSConfig` returns a `*tls.Config` that generates a certificate for whatever hostname the client requests via SNI. Caching is opt-in: pass a cache from the `cache` package to `New` via `WithCache` to reuse certificates across connections, and tune entry expiry with `WithCacheMaxAge`. Without a cache, a certificate is regenerated for every request.

**Production use:** the cache is off by default — enable it with `WithCache(hqgotlscache.NewInMemory(maxSize))`, sized to the number of distinct hosts served, and set `WithCacheMaxAge` well below the leaf validity (24 hours for SNI-driven issuance). For dynamic per-host issuance, consider `WithCAKeyType(KeyTypeECDSAP256)`: ECDSA-P256 leaf generation is markedly faster than RSA-2048.

Note that the `GetCertificate` hook mints a new key pair for every distinct requested hostname, so an Internet-facing server should restrict issuance — see [Restricting Issuance to Known Hosts](#serving-restricting-issuance-to-known-hosts) — to avoid CPU exhaustion from unbounded certificate generation.

```go
package main

import (
	"log"
	"net/http"
	"time"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
	hqgotlscache "github.com/hueristiq/hq-lib-tls-go/cache"
)

func main() {
	// Generate or load the CA certificate and key.
	caCert, caKey, err := hqgotlsauthority.GenerateCACertificatePrivateKey(
		hqgotlsauthority.WithCACommonName("My Root CA"),
	)
	if err != nil {
		log.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Initialize the certificate cache and the CertificateAuthority.
	certificateCache, err := hqgotlscache.NewInMemory(1024)
	if err != nil {
		log.Fatalf("Failed to initialize certificate cache: %v", err)
	}

	ca, err := hqgotlsauthority.New(caCert, caKey,
		hqgotlsauthority.WithCache(certificateCache),
		hqgotlsauthority.WithCacheMaxAge(6*time.Hour),
	)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Build a TLS configuration with dynamic, SNI-driven certificates.
	tlsConfig := ca.NewTLSConfig()

	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, TLS with SNI!"))
		}),
	}

	log.Println("Starting TLS server on :443")

	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
```

Because the certificates are signed by a self-signed CA, clients must trust `caCert` (for example, by adding it to their root pool) for the handshake to succeed. If a client connects without SNI, use `NewTLSConfigWithHost` to supply a default hostname.

The returned configuration requires TLS 1.2 or higher and advertises the `h2` and `http/1.1` ALPN protocols by default; pass `WithNextProtos` to change them, or call it with no arguments to disable ALPN for non-HTTP servers. To get the same bundled certificate (leaf plus CA chain, with the `Leaf` field populated) outside of a server, call `ca.TLSCertificate("example.com")`.

### Serving: Restricting Issuance to Known Hosts

The `GetCertificate` hook mints a new key pair for every distinct requested hostname. On an Internet-facing server, restrict issuance to the hostnames you actually serve with `WithAllowedHosts`; a handshake for any other name fails before any key generation happens:

```go
tlsConfig := ca.NewTLSConfig(hqgotlsauthority.WithAllowedHosts("example.com", "app.example.com"))
```

Names are normalized exactly like requested SNI names (port stripped, case folded, trailing dot removed), so "Example.COM." and "example.com" are the same entry. A client that sends no SNI falls through to the wrapped configuration: `NewTLSConfig` errors, `NewTLSConfigWithHost` substitutes its default hostname. Calling `WithAllowedHosts` with no hosts rejects every SNI name.

### Probing: Connecting to a TLS Server

The `probe` package connects to a TLS server in one of four modes and returns one unified result: the negotiated version and cipher, the ALPN protocol, the certificate chain as raw DER, and — in zcrypto mode — the captured ClientHello and ServerHello messages.

```go
package main

import (
	"context"
	"log"

	hqgotlsprobe "github.com/hueristiq/hq-lib-tls-go/probe"
)

func main() {
	prober, err := hqgotlsprobe.New(
		hqgotlsprobe.WithMode(hqgotlsprobe.ModeAuto), // ztls first, ctls fallback (the default)
		hqgotlsprobe.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create prober: %v", err)
	}

	result, err := prober.Probe(context.Background(), "example.com:443")
	if err != nil {
		log.Fatalf("Failed to probe: %v", err)
	}

	log.Printf("%s negotiated TLS %#x with cipher %#x", result.Host, result.TLSVersion, result.CipherSuite)
	log.Printf("captured %d certificates and a %d-byte ServerHello", len(result.Certificates), len(result.ServerHello))
}
```

The modes:

- `ModeAuto` — zcrypto first, standard library fallback (default).
- `ModeZTLS` — zmap/zcrypto, with raw handshake capture; tolerates old and unusual servers.
- `ModeCTLS` — the standard library's crypto/tls; no raw capture.
- `ModeOpenSSL` — shells out to the OpenSSL binary (`s_client`); needs OpenSSL on PATH or `WithOpenSSLBinary`.

Use `WithPreHandshake(true)` to abort the zcrypto handshake right after the ServerHello and certificates arrive, skipping the client's key exchange for faster certificate gathering (effective up to TLS 1.2). `WithServerName`, `WithCipherSuites`, `WithMinVersion`/`WithMaxVersion`, `WithNextProtos`, and `WithProxy` (SOCKS5) cover the remaining dialing knobs.

### Probing: Computing JA3/JA3S Fingerprints

The `probe/fingerprint` package turns captured handshake messages into JA3 and JA3S segments and their canonical MD5 digests:

```go
package main

import (
	"context"
	"log"

	hqgotlsfingerprint "github.com/hueristiq/hq-lib-tls-go/probe/fingerprint"
	hqgotlsprobe "github.com/hueristiq/hq-lib-tls-go/probe"
)

func main() {
	prober, err := hqgotlsprobe.New(hqgotlsprobe.WithMode(hqgotlsprobe.ModeZTLS))
	if err != nil {
		log.Fatalf("Failed to create prober: %v", err)
	}

	result, err := prober.Probe(context.Background(), "example.com:443")
	if err != nil {
		log.Fatalf("Failed to probe: %v", err)
	}

	ja3, err := hqgotlsfingerprint.JA3(result.ClientHello)
	if err != nil {
		log.Fatalf("Failed to compute JA3: %v", err)
	}

	ja3s, err := hqgotlsfingerprint.JA3S(result.ServerHello)
	if err != nil {
		log.Fatalf("Failed to compute JA3S: %v", err)
	}

	log.Printf("JA3: %s", hqgotlsfingerprint.Digest(ja3))
	log.Printf("JA3S: %s", hqgotlsfingerprint.Digest(ja3s))
}
```

### Probing: Computing the JARM Fingerprint

`Prober.JARM` sends the ten crafted ClientHello probes defined by the JARM specification over raw TCP and fuzzy-hashes the server's responses — no handshake completes:

```go
prober, err := hqgotlsprobe.New(hqgotlsprobe.WithTimeout(5*time.Second))
if err != nil {
	log.Fatalf("Failed to create prober: %v", err)
}

jarm, err := prober.JARM(context.Background(), "example.com:443")
if err != nil {
	log.Fatalf("Failed to compute JARM: %v", err)
}

log.Printf("JARM: %s", jarm)
```

### Probing: Analyzing Certificates

The `cert` package parses the chain a probe captured, inspects it, and checks trust and revocation:

```go
package main

import (
	"context"
	"log"
	"time"

	hqgotlscert "github.com/hueristiq/hq-lib-tls-go/cert"
	hqgotlsprobe "github.com/hueristiq/hq-lib-tls-go/probe"
)

func main() {
	prober, err := hqgotlsprobe.New()
	if err != nil {
		log.Fatalf("Failed to create prober: %v", err)
	}

	result, err := prober.Probe(context.Background(), "example.com:443")
	if err != nil {
		log.Fatalf("Failed to probe: %v", err)
	}

	chain, err := hqgotlscert.Parse(result.Certificates)
	if err != nil {
		log.Fatalf("Failed to parse chain: %v", err)
	}

	leaf := chain[0]

	log.Printf("subject: %s", leaf.Subject.CommonName)
	log.Printf("issuer: %s", leaf.Issuer.CommonName)
	log.Printf("valid until: %s", leaf.NotAfter)
	log.Printf("SHA-256: %s", leaf.SHA256())
	log.Printf("covers example.com: %v", leaf.CoversHost("example.com"))
	log.Printf("expired: %v", leaf.Expired(time.Now()))
	log.Printf("self-signed: %v", leaf.SelfSigned())
	log.Printf("mismatched: %v", leaf.Mismatched("example.com"))

	if untrusted, _ := hqgotlscert.Untrusted(result.Certificates, "example.com"); untrusted {
		log.Println("a client with the system root store would reject this chain")
	}

	if revoked, _ := hqgotlscert.Revoked(result.Certificates); revoked {
		log.Println("the leaf certificate has been revoked")
	}
}
```

## Contributing

Contributions are welcome and encouraged! Feel free to submit [Pull Requests](https://github.com/hueristiq/hq-lib-tls-go/pulls) or report [Issues](https://github.com/hueristiq/hq-lib-tls-go/issues). For more details, check out the [contribution guidelines](https://github.com/hueristiq/hq-lib-tls-go/blob/main/CONTRIBUTING.md).

A big thank you to all the [contributors](https://github.com/hueristiq/hq-lib-tls-go/graphs/contributors) for your ongoing support!

![contributors](https://contrib.rocks/image?repo=hueristiq/hq-lib-tls-go&max=500)

## Licensing

This package is licensed under the [MIT license](https://opensource.org/license/mit). You are free to use, modify, and distribute it, as long as you follow the terms of the license. You can find the full license text in the repository - [Full MIT license text](https://github.com/hueristiq/hq-lib-tls-go/blob/master/LICENSE).

The embedded cipher classification table is generated from the [ciphersuite.info](https://ciphersuite.info) dataset; see `probe/ciphers/gen` for the generator. The JARM implementation follows the [salesforce/jarm](https://github.com/salesforce/jarm) specification (BSD 3-Clause); the JA3/JA3S implementation follows the [salesforce/ja3](https://github.com/salesforce/ja3) specification (BSD 3-Clause).
