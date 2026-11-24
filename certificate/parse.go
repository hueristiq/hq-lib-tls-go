package certificate

import (
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/pem"
	"net"
	"strings"
	"time"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
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

// Parse parses a DER certificate chain (leaf first) with the Go standard
// library's crypto/x509.
func Parse(chainDER [][]byte) (certificates []*Certificate, err error) {
	if len(chainDER) == 0 {
		err = hqgoerrors.New("invalid input, certificate chain is empty")

		return nil, err
	}

	certificates = make([]*Certificate, 0, len(chainDER))

	for _, raw := range chainDER {
		var certificate *Certificate

		certificate, err = parseOne(raw)
		if err != nil {
			err = hqgoerrors.Wrap(err, "parsing certificate")

			return nil, err
		}

		certificates = append(certificates, certificate)
	}

	return certificates, nil
}

// parseOne parses a single DER certificate with the Go standard library and
// extracts the metadata.
func parseOne(raw []byte) (certificate *Certificate, err error) {
	if len(raw) == 0 {
		err = hqgoerrors.New("invalid input, certificate is empty")

		return nil, err
	}

	parsed, err := x509.ParseCertificate(raw)
	if err != nil {
		err = hqgoerrors.Stack(err)

		return nil, err
	}

	return extractCertificate(parsed), nil
}

// extractCertificate copies the metadata of a standard library certificate
// into the package's Certificate type.
func extractCertificate(certificate *x509.Certificate) (extracted *Certificate) {
	extracted = &Certificate{
		Raw:                   certificate.Raw,
		RawSubject:            certificate.RawSubject,
		RawIssuer:             certificate.RawIssuer,
		Subject:               subjectFrom(&certificate.Subject),
		Issuer:                subjectFrom(&certificate.Issuer),
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

// subjectFrom converts a standard library pkix.Name into a Subject.
func subjectFrom(name *stdpkix.Name) (subject Subject) {
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
func normalizeHost(host string) (normalized string) {
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}

	normalized = strings.TrimSuffix(strings.ToLower(host), ".")

	return normalized
}

// PEMBlock converts the certificate to a "CERTIFICATE" PEM block, per
// [RFC 7468](https://www.rfc-editor.org/info/rfc7468/).
func (c *Certificate) PEMBlock() (pemBytes []byte) {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	}

	return pem.EncodeToMemory(block)
}
