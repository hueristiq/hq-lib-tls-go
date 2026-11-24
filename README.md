# hq-lib-tls-go

![made with go](https://img.shields.io/badge/made%20with-Go-1E90FF.svg) [![go reference](https://pkg.go.dev/badge/github.com/hueristiq/hq-lib-tls-go.svg)](https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go) [![license](https://img.shields.io/badge/license-MIT-gray.svg?color=1E90FF)](https://github.com/hueristiq/hq-lib-tls-go/blob/main/LICENSE) ![maintenance](https://img.shields.io/badge/maintained%3F-yes-1E90FF.svg) [![open issues](https://img.shields.io/github/issues-raw/hueristiq/hq-lib-tls-go.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-lib-tls-go/issues?q=is:issue+is:open) [![closed issues](https://img.shields.io/github/issues-closed-raw/hueristiq/hq-lib-tls-go.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-lib-tls-go/issues?q=is:issue+is:closed)

`hq-lib-tls-go` is a [Go](https://golang.org/) package for serving and inspecting TLS.

## Resources

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
	- [Generating a CA certificate](#generating-a-ca-certificate)
	- [Choosing the key algorithm](#choosing-the-key-algorithm)
	- [Loading a certificate from files](#loading-a-certificate-from-files)
	- [Loading a CA from PEM bytes](#loading-a-ca-from-pem-bytes)
	- [Generating a TLS certificate](#generating-a-tls-certificate)
	- [Signing a certificate signing request (CSR)](#signing-a-certificate-signing-request-csr)
	- [Configuring a TLS server with SNI](#configuring-a-tls-server-with-sni)
	- [Restricting issuance to known hosts](#restricting-issuance-to-known-hosts)
	- [Connecting to a TLS server](#connecting-to-a-tls-server)
	- [Computing JA3/JA3S fingerprints](#computing-ja3ja3s-fingerprints)
	- [Computing the JARM fingerprint](#computing-the-jarm-fingerprint)
	- [Analyzing certificates](#analyzing-certificates)
- [Contributing](#contributing)
- [Licensing](#licensing)

## Features

- **Certificate authority:** generate RSA-2048, ECDSA P-256, or Ed25519 CAs and issue leaves for DNS, IP, email, or URI names.
- **SNI server:** per-host certificates, TLS 1.2 minimum, ALPN, `WithAllowedHosts`, and optional caching.
- **Native TLS client:** SSL 3.0 through TLS 1.3, export cipher suites, full decrypted handshake traces, and a `crypto/tls`-familiar API.
- **Fingerprints:** JA3/JA3S segments and JARM from ten ClientHello probes.
- **Certificate analysis:** tolerant chain parsing, metadata, hostname coverage, digests, trust, and revocation.
- **Cipher classification:** embedded suites marked insecure, weak, secure, or recommended, with IANA and OpenSSL names.

## Installation

To install `hq-lib-tls-go`, run the following command in your Go project:

```bash
go get github.com/hueristiq/hq-lib-tls-go@latest
```

Requires Go 1.26.0 or later.

## Usage

The serving API lives in the `authority` subpackage; the client API lives in the module root, `client`, `ciphers`, `fingerprint`, `certificate`, and `certificate/verify`. The examples below import them under the `hqgotlsauthority`, `hqgotls`, `hqgotlsclient`, `hqgotlsciphers`, `hqgotlsfingerprint`, `hqgotlscertificate`, and `hqgotlscertificateverify` aliases.

```go
import (
	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
	hqgotlsauthoritycache "github.com/hueristiq/hq-lib-tls-go/authority/cache"
	hqgotlscertificate "github.com/hueristiq/hq-lib-tls-go/certificate"
	hqgotls "github.com/hueristiq/hq-lib-tls-go"
	hqgotlsfingerprint "github.com/hueristiq/hq-lib-tls-go/fingerprint"
	hqgotlscertificateverify "github.com/hueristiq/hq-lib-tls-go/certificate/verify"
	hqgotlsclient "github.com/hueristiq/hq-lib-tls-go/client"
	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)
```

The snippets below are illustrative.

### Generating a CA certificate

Use `GenerateCACertificatePrivateKey` to create a self-signed CA certificate and its private key. By default it generates a 2048-bit RSA key; see [Choosing the Key Algorithm](#choosing-the-key-algorithm) to select ECDSA or Ed25519. Persist the result to PEM files with `SaveCertificatePrivateKeyToFiles`.

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

### Choosing the key algorithm

Pass `WithCAKeyType` to control the CA's private key algorithm. Every leaf certificate inherits the CA's algorithm, so an ECDSA or Ed25519 CA also makes per-host issuance faster. That helps the SNI server below, which generates a key per hostname.

```go
caCert, caKey, err := hqgotlsauthority.GenerateCACertificatePrivateKey(
	hqgotlsauthority.WithCACommonName("My Root CA"),
	hqgotlsauthority.WithCAKeyType(hqgotlsauthority.KeyTypeECDSAP256),
)
```

Available key types: `KeyTypeRSA2048` (default), `KeyTypeECDSAP256`, and `KeyTypeEd25519`.

### Loading a certificate from files

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

### Loading a CA from PEM bytes

When the certificate and key are already in memory (for example, read from a secret store), construct the authority directly with `NewFromPEM`.

```go
ca, err := hqgotlsauthority.NewFromPEM(caCertPEM, caKeyPEM)
if err != nil {
	log.Fatalf("Failed to initialize CA: %v", err)
}
```

### Generating a TLS certificate

Use a `CA` to issue a leaf certificate for specific hosts. Each host is routed into the matching Subject Alternative Name field: DNS name, IP address, email address, or URI.

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

	// Initialize the CA.
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

### Signing a certificate signing request (CSR)

`SignCSR` signs a CSR with the CA's private key: the client keeps its private key, and the CA never sees it. The CSR's signature is verified before signing, its subject alternative names are copied to the certificate, and the default extended key usage is client authentication, suited to issuing client certificates for mutual TLS. The same `IssueOption`s as `GenerateTLSCertificate` override the defaults.

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

	// Initialize the CA.
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

### Configuring a TLS server with SNI

`NewTLSConfig` returns a `*tls.Config` that generates a certificate for whatever hostname the client requests via SNI. Caching is opt-in: pass a cache from the `cache` package to `New` via `WithCache` to reuse certificates across connections, and tune entry expiry with `WithCacheMaxAge`. Without a cache, a certificate is regenerated for every request.

**Production use:** the cache is off by default. Enable it with `WithCache(hqgotlsauthoritycache.NewInMemory(maxSize))`, sized to the number of distinct hosts served, and set `WithCacheMaxAge` well below the leaf validity (24 hours for SNI-driven issuance). For dynamic per-host issuance, consider `WithCAKeyType(KeyTypeECDSAP256)`: ECDSA-P256 leaf generation is faster than RSA-2048.

The `GetCertificate` hook mints a new key pair for every distinct requested hostname. An Internet-facing server should restrict issuance (see [Restricting issuance to known hosts](#restricting-issuance-to-known-hosts)) to avoid CPU exhaustion from unbounded certificate generation.

```go
package main

import (
	"log"
	"net/http"
	"time"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
	hqgotlsauthoritycache "github.com/hueristiq/hq-lib-tls-go/authority/cache"
)

func main() {
	// Generate or load the CA certificate and key.
	caCert, caKey, err := hqgotlsauthority.GenerateCACertificatePrivateKey(
		hqgotlsauthority.WithCACommonName("My Root CA"),
	)
	if err != nil {
		log.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Initialize the certificate cache and the CA.
	certificateCache, err := hqgotlsauthoritycache.NewInMemory(1024)
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

### Restricting issuance to known hosts

The `GetCertificate` hook mints a new key pair for every distinct requested hostname. On an Internet-facing server, restrict issuance to the hostnames you serve with `WithAllowedHosts`; a handshake for any other name fails before any key generation happens:

```go
tlsConfig := ca.NewTLSConfig(hqgotlsauthority.WithAllowedHosts("example.com", "app.example.com"))
```

Names are normalized exactly like requested SNI names (port stripped, case folded, trailing dot removed), so "Example.COM." and "example.com" are the same entry. A client that sends no SNI falls through to the wrapped configuration: `NewTLSConfig` errors, `NewTLSConfigWithHost` substitutes its default hostname. Calling `WithAllowedHosts` with no hosts rejects every SNI name.

### Connecting to a TLS server

The root package connects through the native engine in `client`, returning one unified result: the negotiated version and cipher, the ALPN protocol, the DER certificate chain, parsed certificate metadata, and the decrypted handshake trace.

```go
package main

import (
	"context"
	"log"
	"time"

	hqgotls "github.com/hueristiq/hq-lib-tls-go"
	hqgotlsclient "github.com/hueristiq/hq-lib-tls-go/client"
)

func main() {
	client, err := hqgotls.New(
		hqgotls.WithTimeout(5*time.Second),
		hqgotls.WithHandshakeLogger(func(event hqgotlsclient.HandshakeEvent) {
			log.Println(event)
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	result, err := client.Inspect(context.Background(), "example.com:443")
	if err != nil {
		log.Fatalf("Failed to inspect: %v", err)
	}

	log.Printf("%s negotiated %s with %s", result.Host, hqgotlsclient.VersionName(result.TLSVersion), hqgotlsclient.CipherSuiteName(result.CipherSuite))
	log.Printf("captured %d certificates", len(result.Certificates))
	log.Printf("handshake messages: %d", len(result.Trace))
}
```

There is no connection mode. `WithCipherSuites`, `WithMinVersion`/`WithMaxVersion`, `WithNextProtos`, `WithServerName`, `WithProxy` (SOCKS5), `WithRootCAs`, `WithInsecureSkipVerify`, `WithAllowExportCipherSuites`, and `WithClientHelloSpec` cover the connection knobs.

### Using the native TLS client directly

The `client` subpackage exposes a `crypto/tls`-familiar client when the probe result shape is too high-level. Use `client.NewConn` to wrap an existing `net.Conn`.

```go
package main

import (
	"context"
	"log"
	"time"

	hqgotlsclient "github.com/hueristiq/hq-lib-tls-go/client"
)

func main() {
	connection, err := hqgotlsclient.DialContext(context.Background(), "tcp", "example.com:443", &hqgotlsclient.Config{
		ServerName: "example.com",
		MinVersion: hqgotlsclient.VersionTLS12,
		MaxVersion: hqgotlsclient.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer connection.Close()

	state := connection.ConnectionState()
	log.Printf("negotiated %s with %s", hqgotlsclient.VersionName(state.Version), hqgotlsclient.CipherSuiteName(state.CipherSuite))

	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	for _, event := range connection.HandshakeTrace() {
		log.Println(event)
	}
}
```

### Legacy versions and export ciphers

Set `MinVersion` to `VersionSSL30`, `VersionTLS10`, or `VersionTLS11` to use the legacy record rules. Export suites are rejected unless `AllowExportCipherSuites` is set.

```go
connection, err := hqgotlsclient.DialContext(context.Background(), "tcp", "legacy.example:443", &hqgotlsclient.Config{
	InsecureSkipVerify:      true,
	MinVersion:              hqgotlsclient.VersionSSL30,
	MaxVersion:              hqgotlsclient.VersionTLS10,
	CipherSuites:            []uint16{0x0003, 0x0008, 0x000A}, // RC4-40, DES40, 3DES
	AllowExportCipherSuites: true,
})
```

### Handshake logging

`HandshakeLogger` streams events during the handshake, and `HandshakeTrace` / `HandshakeLog` return the accumulated trace. Because the engine owns the key schedule, every message is logged in plaintext, including TLS 1.3's encrypted handshake flight. The trace's `Raw` field is the handshake message bytes expected by the `fingerprint` package.

```go
trace := connection.HandshakeTrace()

for _, event := range trace {
	if event.Name == "ClientHello" {
		ja3, err := hqgotlsfingerprint.JA3(event.Raw)
		if err == nil {
			log.Printf("JA3: %s", hqgotlsfingerprint.Digest(ja3))
		}
	}
}
```

### Computing JA3/JA3S fingerprints

The `fingerprint` package computes JA3 and JA3S from captured handshake bytes and JARM by dialing the target. Supply a ClientHello or ServerHello captured elsewhere, for example from a packet capture:

```go
package main

import (
	"log"

	hqgotlsfingerprint "github.com/hueristiq/hq-lib-tls-go/fingerprint"
)

func fingerprintHandshake(clientHelloBytes, serverHelloBytes []byte) error {
	ja3, err := hqgotlsfingerprint.JA3(clientHelloBytes)
	if err != nil {
		return err
	}

	ja3s, err := hqgotlsfingerprint.JA3S(serverHelloBytes)
	if err != nil {
		return err
	}

	log.Printf("JA3: %s", hqgotlsfingerprint.Digest(ja3))
	log.Printf("JA3S: %s", hqgotlsfingerprint.Digest(ja3s))

	return nil
}

func main() {
	if err := fingerprintHandshake(nil, nil); err != nil {
		log.Fatal(err)
	}
}
```

### Computing the JARM fingerprint

`Client.JARM` sends the ten crafted ClientHello probes defined by the JARM specification over raw TCP and fuzzy-hashes the server's responses. No handshake completes. The implementation lives in `fingerprint.JARM`, which accepts a dialer and timeout:

```go
client, err := hqgotls.New(hqgotls.WithTimeout(5*time.Second))
if err != nil {
	log.Fatalf("Failed to create client: %v", err)
}

jarm, err := client.JARM(context.Background(), "example.com:443")
if err != nil {
	log.Fatalf("Failed to compute JARM: %v", err)
}

log.Printf("JARM: %s", jarm)
```

### Analyzing certificates

The `certificate` package parses and analyzes the chain an inspection captured. The `certificate/verify` package checks trust and revocation:

```go
package main

import (
	"context"
	"log"
	"time"

	hqgotlscertificate "github.com/hueristiq/hq-lib-tls-go/certificate"
	hqgotlscertificateverify "github.com/hueristiq/hq-lib-tls-go/certificate/verify"
	hqgotls "github.com/hueristiq/hq-lib-tls-go"
)

func main() {
	client, err := hqgotls.New()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	result, err := client.Inspect(context.Background(), "example.com:443")
	if err != nil {
		log.Fatalf("Failed to inspect: %v", err)
	}

	chain, err := hqgotlscertificate.Parse(result.Certificates)
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

	if untrusted, _ := hqgotlscertificateverify.Untrusted(result.Certificates, "example.com"); untrusted {
		log.Println("a client with the system root store would reject this chain")
	}

	if revoked, _ := hqgotlscertificateverify.Revoked(result.Certificates); revoked {
		log.Println("the leaf certificate has been revoked")
	}
}
```

The embedded cipher classification table is generated from the [ciphersuite.info](https://ciphersuite.info) dataset; see `cmd/ciphersgen` for the generator. JA3 and JA3S summarize a captured ClientHello and ServerHello, and JARM fingerprints a server by sending ten crafted ClientHello probes.

### Cipher classification

```go
for _, suite := range hqgotlsciphers.BySecurity(hqgotlsciphers.SecurityInsecure) {
	fmt.Printf("%#04x\n", suite)
}
```

## Contributing

Contributions are welcome and encouraged! Feel free to submit [Pull Requests](https://github.com/hueristiq/hq-lib-tls-go/pulls) or report [Issues](https://github.com/hueristiq/hq-lib-tls-go/issues).

A big thank you to all the [contributors](https://github.com/hueristiq/hq-lib-tls-go/graphs/contributors) for your ongoing support!

![contributors](https://contrib.rocks/image?repo=hueristiq/hq-lib-tls-go&max=500)

## Licensing

This package is licensed under the [MIT license](https://opensource.org/license/mit). You are free to use, modify, and distribute it, as long as you follow the terms of the license. You can find the full license text in the repository - [Full MIT license text](https://github.com/hueristiq/hq-lib-tls-go/blob/main/LICENSE).
