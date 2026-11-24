package certificate

import (
	"crypto/md5"  //nolint:gosec // G501: the report exposes legacy digests for fingerprinting.
	"crypto/sha1" //nolint:gosec // G505: the report exposes legacy digests for fingerprinting.
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// Report aggregates the certificate metadata commonly emitted by TLS
// scanners: subject fields, SANs, serial, digests, wildcard status, and the
// validity and hostname checks.
type Report struct {
	Chain      []*Cert
	Leaf       *Cert
	SubjectCN  string
	SANs       []string
	SubjectOrg []string
	Serial     string
	IssuerCN   string
	NotBefore  time.Time
	NotAfter   time.Time
	Digests    map[string]string
	Wildcard   bool
	Expired    bool
	SelfSigned bool
	Mismatched bool
}

// Analyze parses a DER chain and builds a report for host at now.
func Analyze(chainDER [][]byte, host string, now time.Time) (report *Report, err error) {
	if len(chainDER) == 0 {
		return nil, hqgoerrors.New("invalid input, certificate chain is empty")
	}

	chain, err := Parse(chainDER)
	if err != nil {
		return nil, err
	}

	leaf := chain[0]

	digests, err := leaf.Digests([]string{"md5", "sha1", "sha256"})
	if err != nil {
		return nil, err
	}

	report = &Report{
		Chain:      chain,
		Leaf:       leaf,
		SubjectCN:  leaf.Subject.CommonName,
		SANs:       leaf.UniqueDNSNames(),
		SubjectOrg: append([]string(nil), leaf.Subject.Organization...),
		Serial:     leaf.SerialNumber,
		IssuerCN:   leaf.Issuer.CommonName,
		NotBefore:  leaf.NotBefore,
		NotAfter:   leaf.NotAfter,
		Digests:    digests,
		Wildcard:   leaf.Wildcard(),
		Expired:    leaf.Expired(now),
		SelfSigned: leaf.SelfSigned(),
	}

	if host != "" {
		report.Mismatched = leaf.Mismatched(host)
	}

	return report, nil
}

// Wildcard reports whether the certificate carries at least one wildcard DNS
// name.
func (c *Cert) Wildcard() (wildcard bool) {
	if c == nil {
		return false
	}

	for _, name := range c.DNSNames {
		if strings.HasPrefix(name, "*.") {
			return true
		}
	}

	return false
}

// UniqueDNSNames returns the certificate's DNS names with duplicates removed,
// preserving their order.
func (c *Cert) UniqueDNSNames() (names []string) {
	if c == nil {
		return nil
	}

	seen := make(map[string]struct{}, len(c.DNSNames))

	for _, name := range c.DNSNames {
		if _, ok := seen[name]; ok {
			continue
		}

		seen[name] = struct{}{}

		names = append(names, name)
	}

	return names
}

// Digest returns the hex digest of the certificate's DER bytes using
// algorithm: "md5", "sha1", or "sha256".
func (c *Cert) Digest(algorithm string) (digest string, err error) {
	if c == nil {
		return "", hqgoerrors.New("invalid input, certificate is nil")
	}

	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "md5":
		sum := md5.Sum(c.Raw) //nolint:gosec // G401: exposed for fingerprinting only.
		digest = hex.EncodeToString(sum[:])
	case "sha1":
		sum := sha1.Sum(c.Raw) //nolint:gosec // G401: exposed for fingerprinting only.
		digest = hex.EncodeToString(sum[:])
	case "sha256":
		sum := sha256.Sum256(c.Raw)
		digest = hex.EncodeToString(sum[:])
	default:
		err = hqgoerrors.Errorf("invalid input, unknown digest algorithm: %q", algorithm)
	}

	return digest, err
}

// Digests returns the requested hex digests, keyed by algorithm. Every
// algorithm must be one of "md5", "sha1", or "sha256".
func (c *Cert) Digests(algorithms []string) (digests map[string]string, err error) {
	digests = make(map[string]string, len(algorithms))

	for _, algorithm := range algorithms {
		var digest string

		digest, err = c.Digest(algorithm)
		if err != nil {
			return nil, err
		}

		digests[strings.ToLower(algorithm)] = digest
	}

	return digests, nil
}
