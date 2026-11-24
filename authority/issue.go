package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"time"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	hqgotlsauthoritycache "github.com/hueristiq/hq-lib-tls-go/authority/cache"
)

// GenerateTLSCertificate generates a new X.509 TLS certificate and its corresponding private key.
//
// This method creates a private key (matching the CA's key type: RSA, ECDSA, or Ed25519) and a TLS certificate signed by the CA,
// based on the provided configuration options and hostnames. The certificate includes a random serial number and a subject key
// identifier (SKI); its key usage is digital signature, plus key encipherment for RSA keys only. Hostnames are parsed to
// determine if they represent IP addresses, email addresses, URIs, or DNS names, and are added to the appropriate certificate
// fields; non-ASCII DNS names are converted to their A-label (punycode) form, since a DNS SAN must be ASCII. The certificate's
// CommonName defaults to the first host, and its expiry is clamped to the CA's expiry so a leaf never outlives its CA; a
// requested validity that starts at or after the CA's expiry is rejected.
//
// By default the Common Name is the first host, the Organization is empty, the
// extended key usages are derived from the SAN kinds present (see
// [WithTLSExtKeyUsage]), the validity period is 365 days from now, and the
// leaf's key algorithm matches the CA's: an RSA CA passes its key size on to
// the leaf, and an ECDSA CA passes on its curve.
func (ca *CertificateAuthority) GenerateTLSCertificate(hosts []string, ofs ...IssueOptionFunc) (certificate *x509.Certificate, privateKey crypto.Signer, err error) {
	if ca == nil {
		err = errCertificateAuthorityNil

		return nil, nil, err
	}

	if ca.caCertificate == nil || ca.caCertificatePrivateKey == nil {
		err = errCertificateAuthorityNotInitialized

		return nil, nil, err
	}

	if len(hosts) == 0 {
		err = hqgoerrors.New("invalid input, hosts list is empty")

		return nil, nil, err
	}

	for _, host := range hosts {
		if host == "" {
			err = hqgoerrors.New("invalid input, empty hostname in hosts list")

			return nil, nil, err
		}
	}

	opts := &IssueOptions{
		CommonName: hosts[0],
		ValidFrom:  time.Now(),
		ValidFor:   365 * 24 * time.Hour,
	}

	for _, f := range ofs {
		if f == nil {
			continue
		}

		f(opts)
	}

	if opts.CommonName == "" {
		err = hqgoerrors.New("invalid input, CommonName is empty")

		return nil, nil, err
	}

	if err := validateValidFor(opts.ValidFor); err != nil {
		return nil, nil, err
	}

	ops := ca.operations()

	switch caKey := ca.caCertificatePrivateKey.(type) {
	case *rsa.PrivateKey:
		keySize := caKey.N.BitLen()

		privateKey, err = ops.rsaGenerateKey(rand.Reader, keySize)
		if err != nil {
			err = hqgoerrors.Wrapf(err, "generating RSA private key (%d bits)", keySize)

			return nil, nil, err
		}
	case *ecdsa.PrivateKey:
		curve := caKey.Curve
		if curve == nil {
			curve = elliptic.P256()
		}

		privateKey, err = ops.ecdsaGenerateKey(curve, rand.Reader)
		if err != nil {
			err = hqgoerrors.Wrapf(err, "generating ECDSA private key (curve %v)", curve)

			return nil, nil, err
		}
	case ed25519.PrivateKey:
		_, privateKey, err = ops.ed25519GenerateKey(rand.Reader)
		if err != nil {
			err = hqgoerrors.Wrap(err, "generating Ed25519 private key")

			return nil, nil, err
		}
	default:
		err = hqgoerrors.Errorf("unsupported CA private key type: %T", caKey)

		return nil, nil, err
	}

	publicKey := privateKey.Public()

	serialNumber, err := generateSerialNumberWith(ops)
	if err != nil {
		err = hqgoerrors.Wrap(err, "generating serial number for certificate")

		return nil, nil, err
	}

	subjectKeyID, err := generateSubjectKeyIDWith(ops, publicKey)
	if err != nil {
		err = hqgoerrors.Wrapf(err, "generating subject key ID for public key (type %T)", publicKey)

		return nil, nil, err
	}

	// Key encipherment is only meaningful for RSA keys (RSA key exchange in
	// TLS 1.2 and below); leave it off ECDSA and Ed25519 certificates.
	keyUsage := x509.KeyUsageDigitalSignature

	if _, ok := publicKey.(*rsa.PublicKey); ok {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	// Clamp the leaf's expiry to the CA's expiry so an issued certificate never
	// outlives the authority that signed it.
	notBefore := opts.ValidFrom.Add(-5 * time.Minute)
	notAfter := opts.ValidFrom.Add(opts.ValidFor)

	if notAfter.After(ca.caCertificate.NotAfter) {
		notAfter = ca.caCertificate.NotAfter
	}

	// A requested validity that starts at or after the CA's expiry cannot be
	// clamped into a usable window: the certificate would expire before it
	// became valid. Reject it instead of issuing an unusable certificate.
	if !notAfter.After(notBefore) {
		err = hqgoerrors.Errorf("invalid input, validity period is empty or negative after clamping to the CA's expiry (ValidFrom: %v, CA expiry: %v)", opts.ValidFrom, ca.caCertificate.NotAfter)

		return nil, nil, err
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
		// Backdate NotBefore by 5 minutes to tolerate modest clock skew between
		// this host and verifying clients.
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: opts.Organization,
		},
		SubjectKeyId: subjectKeyID,
	}

	for _, host := range hosts {
		// Classify each host into the matching Subject Alternative Name field.
		// Order matters: an IP literal, then a bare email address, then a URI
		// (which requires both a scheme and a host), falling back to a DNS name.
		if IP := net.ParseIP(host); IP != nil {
			template.IPAddresses = append(template.IPAddresses, IP)
		} else if isEmailAddress(host) {
			template.EmailAddresses = append(template.EmailAddresses, host)
		} else if uriName, err := url.Parse(host); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			template.URIs = append(template.URIs, uriName)
		} else {
			dnsName, err := dnsNameToASCII(host)
			if err != nil {
				err = hqgoerrors.Wrapf(err, "converting DNS name %q to its ASCII (A-label) form", host)

				return nil, nil, err
			}

			template.DNSNames = append(template.DNSNames, dnsName)
		}
	}

	// Default the extended key usages from the SAN kinds present: server
	// authentication when the certificate names a host, email protection when
	// it names a mailbox. An explicit WithTLSExtKeyUsage always wins.
	extKeyUsage := opts.ExtKeyUsage

	if len(extKeyUsage) == 0 {
		if len(template.DNSNames)+len(template.IPAddresses)+len(template.URIs) > 0 {
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
		}

		if len(template.EmailAddresses) > 0 {
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageEmailProtection)
		}
	}

	template.ExtKeyUsage = extKeyUsage

	certificateDER, err := ops.createCertificate(rand.Reader, template, ca.caCertificate, publicKey, ca.caCertificatePrivateKey)
	if err != nil {
		err = hqgoerrors.Wrapf(err, "creating TLS certificate for hosts %v", hosts)

		return nil, nil, err
	}

	certificate, err = ops.parseCertificate(certificateDER)
	if err != nil {
		err = hqgoerrors.Wrap(err, "parsing generated TLS certificate")

		return nil, nil, err
	}

	return certificate, privateKey, nil
}

// TLSCertificate returns a TLS certificate for the given hostname. The certificate is
// regenerated on every call unless a cache is configured via [WithCache], in which case
// the cached certificate is served while it remains valid (see [WithCacheMaxAge]).
//
// The hostname is normalized before lookup (port stripped, Unicode NFC folded to lowercase, trailing
// dot removed), and concurrent calls for the same host share a single generation.
//
// The returned bundle chains to the CA certificate: Certificate[0] is the leaf
// certificate, Certificate[1] is the CA certificate, and the Leaf field is
// populated.
func (ca *CertificateAuthority) TLSCertificate(hostname string) (certificate *tls.Certificate, err error) {
	if ca == nil {
		err = errCertificateAuthorityNil

		return nil, err
	}

	if ca.caCertificate == nil || ca.caCertificatePrivateKey == nil {
		err = errCertificateAuthorityNotInitialized

		return nil, err
	}

	return ca.getTLSCertificate(hostname)
}

// SignCSR signs a certificate signing request (CSR) with the CA's private key
// and returns the resulting X.509 certificate.
//
// The certificate template is derived from the CSR's public key, subject, and
// subject alternative names, while validity period, extended key usage, and
// subject overrides are applied through the provided options. Key usage is
// digital signature, plus key encipherment when the CSR's public key is RSA.
// When no EKU options are supplied, the certificate defaults to client
// authentication ([x509.ExtKeyUsageClientAuth]). The certificate's expiry is
// clamped to the CA's expiry so a signed certificate never outlives its CA; a
// requested validity that starts at or after the CA's expiry is rejected.
//
// The CSR's signature is verified before signing. The Common Name and
// Organization default to the CSR's subject values and can be overridden with
// [WithTLSCommonName] and [WithTLSOrganization]; the subject alternative names
// (DNS names, IP addresses, email addresses, and URIs) are copied from the CSR.
func (ca *CertificateAuthority) SignCSR(csr *x509.CertificateRequest, ofs ...IssueOptionFunc) (certificate *x509.Certificate, err error) {
	if ca == nil {
		err = errCertificateAuthorityNil

		return nil, err
	}

	if ca.caCertificate == nil || ca.caCertificatePrivateKey == nil {
		err = errCertificateAuthorityNotInitialized

		return nil, err
	}

	if csr == nil {
		err = hqgoerrors.New("invalid input, CSR is nil")

		return nil, err
	}

	if err = csr.CheckSignature(); err != nil {
		err = hqgoerrors.Wrap(err, "verifying CSR signature")

		return nil, err
	}

	opts := &IssueOptions{
		CommonName:   csr.Subject.CommonName,
		Organization: csr.Subject.Organization,
		ValidFrom:    time.Now(),
		ValidFor:     365 * 24 * time.Hour,
	}

	for _, f := range ofs {
		if f == nil {
			continue
		}

		f(opts)
	}

	if opts.CommonName == "" {
		err = hqgoerrors.New("invalid input, CommonName is empty")

		return nil, err
	}

	if err := validateValidFor(opts.ValidFor); err != nil {
		return nil, err
	}

	extKeyUsage := opts.ExtKeyUsage
	if len(extKeyUsage) == 0 {
		extKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		}
	}

	ops := ca.operations()

	serialNumber, err := generateSerialNumberWith(ops)
	if err != nil {
		err = hqgoerrors.Wrap(err, "generating serial number for certificate")

		return nil, err
	}

	subjectKeyID, err := generateSubjectKeyIDWith(ops, csr.PublicKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "generating subject key ID for CSR public key")

		return nil, err
	}

	// Clamp the certificate's expiry to the CA's expiry so a signed certificate
	// never outlives the authority that signed it.
	notBefore := opts.ValidFrom.Add(-5 * time.Minute)
	notAfter := opts.ValidFrom.Add(opts.ValidFor)

	if notAfter.After(ca.caCertificate.NotAfter) {
		notAfter = ca.caCertificate.NotAfter
	}

	// A requested validity that starts at or after the CA's expiry cannot be
	// clamped into a usable window: the certificate would expire before it
	// became valid. Reject it instead of signing an unusable certificate.
	if !notAfter.After(notBefore) {
		err = hqgoerrors.Errorf("invalid input, validity period is empty or negative after clamping to the CA's expiry (ValidFrom: %v, CA expiry: %v)", opts.ValidFrom, ca.caCertificate.NotAfter)

		return nil, err
	}

	// Key encipherment is only meaningful for RSA keys (RSA key exchange in
	// TLS 1.2 and below); leave it off certificates for ECDSA and Ed25519
	// CSR public keys.
	keyUsage := x509.KeyUsageDigitalSignature

	if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		ExtKeyUsage:           extKeyUsage,
		IPAddresses:           csr.IPAddresses,
		KeyUsage:              keyUsage,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: opts.Organization,
			SerialNumber: csr.Subject.SerialNumber,
			Country:      csr.Subject.Country,
			Province:     csr.Subject.Province,
			Locality:     csr.Subject.Locality,
		},
		SubjectKeyId: subjectKeyID,
		URIs:         csr.URIs,
	}

	certificateDER, err := ops.createCertificate(rand.Reader, template, ca.caCertificate, csr.PublicKey, ca.caCertificatePrivateKey)
	if err != nil {
		err = hqgoerrors.Wrap(err, "signing CSR")

		return nil, err
	}

	certificate, err = ops.parseCertificate(certificateDER)
	if err != nil {
		err = hqgoerrors.Wrap(err, "parsing signed CSR certificate")

		return nil, err
	}

	return certificate, nil
}

// NewTLSConfig creates a TLS configuration for use in a TLS server.
//
// If the authority is nil or uninitialized, the returned configuration fails every handshake with
// an error instead of silently serving TLS without dynamic certificates.
//
// Certificates are regenerated per request unless a cache is configured via [WithCache].
// Note that the GetCertificate hook mints a new key pair for every distinct requested hostname;
// pass [WithAllowedHosts] to restrict issuance to known names and avoid CPU exhaustion from
// unbounded certificate generation on Internet-facing servers.
func (ca *CertificateAuthority) NewTLSConfig(ofs ...TLSConfigMutator) (cfg *tls.Config) {
	// A nil authority behaves as an uninitialized one: the returned configuration
	// fails every handshake with an error instead of silently serving TLS without
	// dynamic certificates.
	if ca == nil {
		ca = &CertificateAuthority{}
	}

	cfg = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (certificate *tls.Certificate, err error) {
			if hello == nil {
				err = hqgoerrors.New("invalid input, ClientHelloInfo is nil")

				return nil, err
			}

			host := hello.ServerName

			if host == "" {
				err = hqgoerrors.New("invalid input, missing server name (SNI)")

				return nil, err
			}

			return ca.getTLSCertificate(host)
		},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}

	for _, f := range ofs {
		if f == nil {
			continue
		}

		f(cfg)
	}

	return cfg
}

// NewTLSConfigWithHost creates a TLS configuration for a specific hostname.
//
// Similar to NewTLSConfig, but allows specifying a default hostname to use when SNI is not provided.
// If the authority is nil or uninitialized, the returned configuration fails every handshake with
// an error instead of silently serving TLS without dynamic certificates.
//
// Certificates are regenerated per request unless a cache is configured via [WithCache].
// Note that the GetCertificate hook mints a new key pair for every distinct requested hostname;
// pass [WithAllowedHosts] to restrict issuance to known names and avoid CPU exhaustion from
// unbounded certificate generation on Internet-facing servers.
func (ca *CertificateAuthority) NewTLSConfigWithHost(hostname string, ofs ...TLSConfigMutator) (cfg *tls.Config) {
	// A nil authority behaves as an uninitialized one: the returned configuration
	// fails every handshake with an error instead of silently serving TLS without
	// dynamic certificates.
	if ca == nil {
		ca = &CertificateAuthority{}
	}

	cfg = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (certificate *tls.Certificate, err error) {
			if hello == nil {
				err = hqgoerrors.New("invalid input, ClientHelloInfo is nil")

				return nil, err
			}

			host := hello.ServerName
			if host == "" {
				host = hostname
			}

			return ca.getTLSCertificate(host)
		},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}

	for _, f := range ofs {
		if f == nil {
			continue
		}

		f(cfg)
	}

	return cfg
}

// getTLSCertificate retrieves or generates a TLS certificate for the given hostname.
//
// This internal method checks the configured cache, if any, for an existing certificate for the
// normalized hostname. If a valid cached certificate exists (neither older than cacheMaxAge nor
// expired), it is returned. Otherwise, a new certificate is generated, and stored in the cache
// when one is configured. Concurrent generation for the
// same host is deduplicated: the first caller generates while later callers wait for its result,
// so a burst of simultaneous handshakes pays for a single key generation. The cache is checked a
// second time under the in-flight mutex before a caller becomes the leader, so a certificate
// completed between the first lookup and the lock acquisition is served instead of regenerated.
//
// A panic during generation is recovered and converted into an error: the leader and every
// waiter receive it, and the in-flight entry is removed, so waiting handshake goroutines never
// block forever and a panicking host is not poisoned permanently.
func (ca *CertificateAuthority) getTLSCertificate(hostname string) (certificate *tls.Certificate, err error) {
	host := normalizeHost(hostname)

	if ca.cache != nil {
		if entry, found := ca.cache.Get(host); found && ca.isCacheEntryValid(entry) {
			return entry.Certificate, nil
		}
	}

	// Deduplicate concurrent generation for the same host: the first caller
	// (the leader) generates while later callers wait on the in-flight call.
	ca.inflightMutex.Lock()

	if ca.inflight == nil {
		ca.inflight = make(map[string]*inflightCall)
	}

	if call, exists := ca.inflight[host]; exists {
		ca.inflightMutex.Unlock()

		<-call.done

		return call.certificate, call.err
	}

	// A previous leader may have generated and cached the certificate between
	// the unlocked cache lookup above and this lock acquisition; re-check the
	// cache before becoming the leader so a host never pays for two
	// generations. The mutex makes the completed leader's Set visible here.
	if ca.cache != nil {
		if entry, found := ca.cache.Get(host); found && ca.isCacheEntryValid(entry) {
			ca.inflightMutex.Unlock()

			return entry.Certificate, nil
		}
	}

	call := &inflightCall{done: make(chan struct{})}
	ca.inflight[host] = call

	ca.inflightMutex.Unlock()

	// Publish the outcome to waiters and clear the in-flight entry even when
	// generation panics: without the recover, a panicking leader would leave
	// call.done open forever, deadlocking every waiter and poisoning the host.
	defer func() {
		if recovered := recover(); recovered != nil {
			certificate = nil
			err = hqgoerrors.Errorf("panic while generating certificate for host %q: %v", host, recovered)
		}

		// Writes happen-before close(done), so waiters observe the finished call.
		call.certificate, call.err = certificate, err

		close(call.done)

		ca.inflightMutex.Lock()
		delete(ca.inflight, host)
		ca.inflightMutex.Unlock()
	}()

	certificate, err = ca.generateAndCacheTLSCertificate(host)

	return certificate, err
}

// generateAndCacheTLSCertificate generates a certificate for the host and stores it in the
// cache when one is configured.
//
// Because in-flight generation is deduplicated per host in getTLSCertificate, at most one
// goroutine runs this method for a given host at a time.
func (ca *CertificateAuthority) generateAndCacheTLSCertificate(host string) (certificate *tls.Certificate, err error) {
	leafCertificate, leafPrivateKey, err := ca.GenerateTLSCertificate([]string{host}, WithTLSValidFor(defaultLeafCertificateValidity))
	if err != nil {
		err = hqgoerrors.Wrapf(err, "generating TLS certificate for host %q", host)

		return nil, err
	}

	certificate = &tls.Certificate{
		Certificate: [][]byte{
			leafCertificate.Raw,
			ca.caCertificate.Raw,
		},
		PrivateKey: leafPrivateKey,
		Leaf:       leafCertificate,
	}

	if ca.cache != nil {
		if err = ca.cache.Set(host, &hqgotlsauthoritycache.CertificateCacheEntry{
			Certificate: certificate,
			CreatedAt:   time.Now(),
		}); err != nil {
			return nil, hqgoerrors.Wrapf(err, "caching TLS certificate for host %q", host)
		}
	}

	return certificate, nil
}

// isCacheEntryValid reports whether a cached certificate may still be served: the entry must have
// been stored in the past (a future CreatedAt is never fresh), be younger than the configured
// maximum age, and the certificate itself must not have expired.
func (ca *CertificateAuthority) isCacheEntryValid(entry *hqgotlsauthoritycache.CertificateCacheEntry) (valid bool) {
	if entry.Certificate == nil || entry.Certificate.Leaf == nil {
		return false
	}

	now := time.Now()
	age := now.Sub(entry.CreatedAt)

	return age >= 0 && age < ca.cacheMaxAge && now.Before(entry.Certificate.Leaf.NotAfter)
}

// inflightCall tracks an in-progress certificate generation for a single hostname so that
// concurrent callers can wait for and share its result instead of generating duplicates.
//
// Fields:
//   - done (chan struct{}): closed when generation completes, unblocking any waiting callers.
//   - certificate (*tls.Certificate): the generated certificate; valid once done is closed.
//   - err (error): the generation failure, if any; valid once done is closed.
type inflightCall struct {
	done        chan struct{}
	certificate *tls.Certificate
	err         error
}
