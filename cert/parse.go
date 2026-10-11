package cert

import (
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	zcryptox509 "github.com/zmap/zcrypto/x509"
	zcryptopkix "github.com/zmap/zcrypto/x509/pkix"
)

// Subject is the subject (or issuer) of a certificate.
//
// Fields:
//   - CommonName (string): the common name.
//   - Organization ([]string): the organization names.
//   - OrganizationalUnit ([]string): the organizational unit names.
//   - Country ([]string): the country names.
//   - Locality ([]string): the locality names.
//   - Province ([]string): the state or province names.
type Subject struct {
	CommonName         string
	Organization       []string
	OrganizationalUnit []string
	Country            []string
	Locality           []string
	Province           []string
}

// Certificate is the parsed form of one X.509 certificate.
//
// Fields:
//   - Raw ([]byte): the DER-encoded certificate.
//   - RawSubject ([]byte): the DER-encoded subject name.
//   - RawIssuer ([]byte): the DER-encoded issuer name.
//   - Subject (Subject): the subject.
//   - Issuer (Subject): the issuer.
//   - SerialNumber (string): the serial number, rendered in decimal.
//   - NotBefore (time.Time): the start of the validity period.
//   - NotAfter (time.Time): the end of the validity period.
//   - DNSNames ([]string): the DNS subject alternative names.
//   - IPAddresses ([]string): the IP subject alternative names.
//   - IssuingCertificateURL ([]string): the CA issuer URLs.
//   - OCSPServer ([]string): the OCSP responder URLs.
//   - CRLDistributionPoints ([]string): the CRL distribution point URLs.
type Certificate struct {
	Raw                   []byte
	RawSubject            []byte
	RawIssuer             []byte
	Subject               Subject
	Issuer                Subject
	SerialNumber          string
	NotBefore             time.Time
	NotAfter              time.Time
	DNSNames              []string
	IPAddresses           []string
	IssuingCertificateURL []string
	OCSPServer            []string
	CRLDistributionPoints []string
}

// Parse parses a DER certificate chain (leaf first), preferring zcrypto's
// tolerant parser and falling back to the standard library for each
// certificate.
//
// Parameters:
//   - chainDER ([][]byte): the DER-encoded certificates.
//
// Returns:
//   - certificates ([]*Certificate): the parsed certificates.
//   - err (error): non-nil when the input is empty or a certificate cannot
//     be parsed by either parser.
func Parse(chainDER [][]byte) (certificates []*Certificate, err error) {
	if len(chainDER) == 0 {
		err = errors.New("cert.Parse: invalid input, certificate chain is empty")

		return nil, err
	}

	certificates = make([]*Certificate, 0, len(chainDER))

	for _, raw := range chainDER {
		var certificate *Certificate

		certificate, err = parseOne(raw)
		if err != nil {
			err = fmt.Errorf("cert.Parse: parsing certificate: %w", err)

			return nil, err
		}

		certificates = append(certificates, certificate)
	}

	return certificates, nil
}

// parseOne parses a single DER certificate with zcrypto first and the
// standard library as a fallback, then extracts the metadata.
//
// Parameters:
//   - raw ([]byte): the DER-encoded certificate.
//
// Returns:
//   - certificate (*Certificate): the parsed certificate.
//   - err (error): non-nil when both parsers fail.
func parseOne(raw []byte) (certificate *Certificate, err error) {
	if len(raw) == 0 {
		err = errors.New("cert.parseOne: invalid input, certificate is empty")

		return nil, err
	}

	zcryptoCertificate, zcryptoErr := zcryptox509.ParseCertificate(raw)
	if zcryptoErr == nil {
		return extractFromZCrypto(zcryptoCertificate), nil
	}

	stdlibCertificate, stdlibErr := x509.ParseCertificate(raw)
	if stdlibErr == nil {
		return extractFromStdlib(stdlibCertificate), nil
	}

	err = fmt.Errorf("cert.parseOne: neither parser accepted the certificate (zcrypto: %v; stdlib: %v)", zcryptoErr, stdlibErr)

	return nil, err
}

// extractFromZCrypto copies the metadata of a zcrypto certificate into the
// package's Certificate type.
//
// Parameters:
//   - certificate (*zcryptox509.Certificate): the parsed certificate.
//
// Returns:
//   - extracted (*Certificate): the copied certificate.
func extractFromZCrypto(certificate *zcryptox509.Certificate) (extracted *Certificate) {
	extracted = &Certificate{
		Raw:                   certificate.Raw,
		RawSubject:            certificate.RawSubject,
		RawIssuer:             certificate.RawIssuer,
		Subject:               subjectFromZCrypto(&certificate.Subject),
		Issuer:                subjectFromZCrypto(&certificate.Issuer),
		SerialNumber:          certificate.SerialNumber.String(),
		NotBefore:             certificate.NotBefore,
		NotAfter:              certificate.NotAfter,
		DNSNames:              append([]string(nil), certificate.DNSNames...),
		IPAddresses:           ipStrings(certificate.IPAddresses),
		IssuingCertificateURL: append([]string(nil), certificate.IssuingCertificateURL...),
		OCSPServer:            append([]string(nil), certificate.OCSPServer...),
		CRLDistributionPoints: append([]string(nil), certificate.CRLDistributionPoints...),
	}

	return extracted
}

// extractFromStdlib copies the metadata of a standard library certificate
// into the package's Certificate type.
//
// Parameters:
//   - certificate (*x509.Certificate): the parsed certificate.
//
// Returns:
//   - extracted (*Certificate): the copied certificate.
func extractFromStdlib(certificate *x509.Certificate) (extracted *Certificate) {
	extracted = &Certificate{
		Raw:                   certificate.Raw,
		RawSubject:            certificate.RawSubject,
		RawIssuer:             certificate.RawIssuer,
		Subject:               subjectFromStdlib(&certificate.Subject),
		Issuer:                subjectFromStdlib(&certificate.Issuer),
		SerialNumber:          certificate.SerialNumber.String(),
		NotBefore:             certificate.NotBefore,
		NotAfter:              certificate.NotAfter,
		DNSNames:              append([]string(nil), certificate.DNSNames...),
		IPAddresses:           ipStrings(certificate.IPAddresses),
		IssuingCertificateURL: append([]string(nil), certificate.IssuingCertificateURL...),
		OCSPServer:            append([]string(nil), certificate.OCSPServer...),
		CRLDistributionPoints: append([]string(nil), certificate.CRLDistributionPoints...),
	}

	return extracted
}

// subjectFromZCrypto converts a zcrypto pkix.Name into a Subject.
//
// Parameters:
//   - name (*zcryptopkix.Name): the pkix name to convert.
//
// Returns:
//   - subject (Subject): the converted subject.
func subjectFromZCrypto(name *zcryptopkix.Name) (subject Subject) {
	subject = Subject{
		CommonName:         name.CommonName,
		Organization:       append([]string(nil), name.Organization...),
		OrganizationalUnit: append([]string(nil), name.OrganizationalUnit...),
		Country:            append([]string(nil), name.Country...),
		Locality:           append([]string(nil), name.Locality...),
		Province:           append([]string(nil), name.Province...),
	}

	return subject
}

// subjectFromStdlib converts a standard library pkix.Name into a Subject.
//
// Parameters:
//   - name (*stdpkix.Name): the pkix name to convert.
//
// Returns:
//   - subject (Subject): the converted subject.
func subjectFromStdlib(name *stdpkix.Name) (subject Subject) {
	subject = Subject{
		CommonName:         name.CommonName,
		Organization:       append([]string(nil), name.Organization...),
		OrganizationalUnit: append([]string(nil), name.OrganizationalUnit...),
		Country:            append([]string(nil), name.Country...),
		Locality:           append([]string(nil), name.Locality...),
		Province:           append([]string(nil), name.Province...),
	}

	return subject
}

// ipStrings renders IP addresses as strings.
//
// Parameters:
//   - addresses ([]net.IP): the IP addresses.
//
// Returns:
//   - rendered ([]string): the rendered addresses.
func ipStrings(addresses []net.IP) (rendered []string) {
	rendered = make([]string, 0, len(addresses))

	for _, address := range addresses {
		rendered = append(rendered, address.String())
	}

	return rendered
}

// CoversHost reports whether the certificate covers host: an exact DNS
// name match, a wildcard match (with a single label under the wildcard),
// or an exact IP match. Hosts are compared case-insensitively with a
// trailing dot ignored.
//
// Parameters:
//   - host (string): the hostname or IP to check (with or without port).
//
// Returns:
//   - covered (bool): whether the certificate covers host.
func (c *Certificate) CoversHost(host string) (covered bool) {
	if c == nil {
		return false
	}

	host = normalizeHost(host)

	if ip := net.ParseIP(host); ip != nil {
		for _, address := range c.IPAddresses {
			if address == ip.String() {
				return true
			}
		}

		return false
	}

	for _, dnsName := range c.DNSNames {
		if strings.EqualFold(dnsName, host) {
			return true
		}

		if rest, wildcard := strings.CutPrefix(dnsName, "*."); wildcard && wildcardCovers(host, rest) {
			return true
		}
	}

	return false
}

// wildcardCovers reports whether host is covered by the wildcard label
// "*." + rest: the host must end in "." + rest and carry exactly one
// label where the wildcard sits, so "*.example.com" covers
// "www.example.com" but neither "example.com" nor "a.b.example.com".
//
// Parameters:
//   - host (string): the normalized hostname.
//   - rest (string): the suffix after the wildcard label.
//
// Returns:
//   - covered (bool): whether the wildcard covers host.
func wildcardCovers(host, rest string) (covered bool) {
	suffix := "." + strings.ToLower(rest)

	if !strings.HasSuffix(strings.ToLower(host), suffix) {
		return false
	}

	prefix := strings.TrimSuffix(strings.ToLower(host), suffix)

	if prefix == "" || strings.Contains(prefix, ".") {
		return false
	}

	return true
}

// normalizeHost strips a port, folds to lowercase, and removes a single
// trailing dot, mirroring the normalization used for certificate hostname
// matching.
//
// Parameters:
//   - host (string): the host to normalize.
//
// Returns:
//   - normalized (string): the normalized host.
func normalizeHost(host string) (normalized string) {
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}

	normalized = strings.TrimSuffix(strings.ToLower(host), ".")

	return normalized
}

// PEMBlock converts the certificate to a "CERTIFICATE" PEM block, per
// RFC 7468.
//
// Returns:
//   - pemBytes ([]byte): the PEM-encoded certificate.
func (c *Certificate) PEMBlock() (pemBytes []byte) {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	}

	return pem.EncodeToMemory(block)
}
