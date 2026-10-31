package certificate

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	// revocationTimeout bounds OCSP and CRL fetches during revocation
	// checks.
	revocationTimeout = 5 * time.Second
	// maxRevocationBody bounds OCSP and CRL response bodies.
	maxRevocationBody = 10 << 20
)

// Expired reports whether the certificate's validity period has already
// ended at now.
//
// Parameters:
//   - now (time.Time): the time to compare against.
//
// Returns:
//   - expired (bool): whether the certificate is expired.
func (c *Certificate) Expired(now time.Time) (expired bool) {
	if c == nil {
		return false
	}

	return !now.Before(c.NotAfter)
}

// SelfSigned reports whether the certificate's subject is its own issuer:
// its subject and issuer names are byte-identical.
//
// Returns:
//   - selfSigned (bool): whether the certificate is self-signed.
func (c *Certificate) SelfSigned() (selfSigned bool) {
	if c == nil {
		return false
	}

	return bytes.Equal(c.RawSubject, c.RawIssuer)
}

// Mismatched reports whether the certificate does not cover host.
//
// Parameters:
//   - host (string): the hostname or IP to check.
//
// Returns:
//   - mismatched (bool): whether the certificate does not cover host.
func (c *Certificate) Mismatched(host string) (mismatched bool) {
	return !c.CoversHost(host)
}

// Untrusted reports whether a normal client using the system root store
// would reject the chain when connecting to host. A chain whose leaf
// cannot even be parsed is untrusted by definition, without an error.
//
// Parameters:
//   - chainDER ([][]byte): the DER certificate chain, leaf first.
//   - host (string): the hostname the client would connect to.
//
// Returns:
//   - untrusted (bool): whether the chain fails verification.
//   - err (error): non-nil when the input is empty.
func Untrusted(chainDER [][]byte, host string) (untrusted bool, err error) {
	// A nil pool makes Verify fall back to the system roots, so an error from
	// SystemCertPool needs no separate handling.
	roots, _ := x509.SystemCertPool()

	return untrustedWith(chainDER, host, roots)
}

// untrustedWith reports whether the chain fails verification against the
// given root pool, treating a pool of nil as the system roots.
//
// Parameters:
//   - chainDER ([][]byte): the DER certificate chain, leaf first.
//   - host (string): the hostname the client would connect to.
//   - roots (*x509.CertPool): the roots to verify against; nil selects the system roots.
//
// Returns:
//   - untrusted (bool): whether the chain fails verification.
//   - err (error): non-nil when the input is empty.
func untrustedWith(chainDER [][]byte, host string, roots *x509.CertPool) (untrusted bool, err error) {
	if len(chainDER) == 0 {
		err = errors.New("cert.Untrusted: invalid input, certificate chain is empty")

		return false, err
	}

	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		return true, nil
	}

	intermediates := x509.NewCertPool()

	for _, raw := range chainDER[1:] {
		if certificate, parseErr := x509.ParseCertificate(raw); parseErr == nil {
			intermediates.AddCert(certificate)
		}
	}

	hostname, _, splitErr := net.SplitHostPort(host)
	if splitErr != nil {
		hostname = host
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		DNSName:       hostname,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Roots:         roots,
	})
	if err != nil {
		return true, nil
	}

	return false, nil
}

// Revoked reports whether the leaf certificate has been revoked, checking
// the certificate's OCSP responders first and falling back to its CRL
// distribution points. A responder that is unreachable, empty, or
// inconclusive ("unknown" status) is skipped in favor of the next source;
// only an explicit "revoked" answer reports true.
//
// Parameters:
//   - chainDER ([][]byte): the DER certificate chain, leaf first, with the
//     issuer second when present.
//
// Returns:
//   - revoked (bool): whether a responder explicitly revoked the leaf.
//   - err (error): non-nil when the leaf cannot be parsed.
func Revoked(chainDER [][]byte) (revoked bool, err error) {
	if len(chainDER) == 0 {
		err = errors.New("cert.Revoked: invalid input, certificate chain is empty")

		return false, err
	}

	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		err = fmt.Errorf("cert.Revoked: parsing leaf certificate: %w", err)

		return false, err
	}

	issuer := leaf

	if len(chainDER) > 1 {
		issuer, err = x509.ParseCertificate(chainDER[1])
		if err != nil {
			err = fmt.Errorf("cert.Revoked: parsing issuer certificate: %w", err)

			return false, err
		}
	}

	client := &http.Client{
		Timeout: revocationTimeout,
	}

	for _, url := range leaf.OCSPServer {
		var status int

		status, ocspErr := fetchOCSPStatus(client, leaf, issuer, url)
		if ocspErr != nil {
			continue
		}

		switch status {
		case ocsp.Revoked:
			return true, nil
		case ocsp.Good:
			return false, nil
		}
	}

	for _, url := range leaf.CRLDistributionPoints {
		revoked, crlErr := crlRevokes(client, leaf, url)
		if crlErr != nil {
			continue
		}

		if revoked {
			return true, nil
		}
	}

	return false, nil
}

// fetchOCSPStatus asks an OCSP responder about the leaf's status.
//
// Parameters:
//   - client (*http.Client): the HTTP client.
//   - leaf (*x509.Certificate): the certificate to check.
//   - issuer (*x509.Certificate): the leaf's issuer.
//   - url (string): the responder URL.
//
// Returns:
//   - status (int): the OCSP status.
//   - err (error): non-nil on any transport or verification failure.
func fetchOCSPStatus(client *http.Client, leaf, issuer *x509.Certificate, url string) (status int, err error) {
	request, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return ocsp.Unknown, fmt.Errorf("creating OCSP request: %w", err)
	}

	httpRequest, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(request))
	if err != nil {
		return ocsp.Unknown, fmt.Errorf("building OCSP request for %q: %w", url, err)
	}

	httpRequest.Header.Set("Content-Type", "application/ocsp-request")

	response, err := client.Do(httpRequest)
	if err != nil {
		return ocsp.Unknown, fmt.Errorf("posting OCSP request to %q: %w", url, err)
	}

	defer func() {
		_ = response.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxRevocationBody))
	if err != nil {
		return ocsp.Unknown, fmt.Errorf("reading OCSP response: %w", err)
	}

	parsed, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return ocsp.Unknown, fmt.Errorf("parsing OCSP response from %q: %w", url, err)
	}

	return parsed.Status, nil
}

// crlRevokes checks whether a CRL distribution point revokes the leaf.
//
// Parameters:
//   - client (*http.Client): the HTTP client.
//   - leaf (*x509.Certificate): the certificate to check.
//   - url (string): the CRL URL.
//
// Returns:
//   - revoked (bool): whether the CRL lists the leaf's serial number.
//   - err (error): non-nil on any transport or parsing failure.
func crlRevokes(client *http.Client, leaf *x509.Certificate, url string) (revoked bool, err error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("building CRL request for %q: %w", url, err)
	}

	response, err := client.Do(request)
	if err != nil {
		return false, fmt.Errorf("fetching CRL from %q: %w", url, err)
	}

	defer func() {
		_ = response.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxRevocationBody))
	if err != nil {
		return false, fmt.Errorf("reading CRL: %w", err)
	}

	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return false, fmt.Errorf("parsing CRL from %q: %w", url, err)
	}

	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}
