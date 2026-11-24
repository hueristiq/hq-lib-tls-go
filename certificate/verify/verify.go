package verify

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

const (
	// revocationTimeout bounds OCSP and CRL fetches during revocation checks.
	revocationTimeout = 5 * time.Second
	// maxRevocationBody bounds OCSP and CRL response bodies.
	maxRevocationBody = 10 << 20
)

// Untrusted reports whether a normal client using the system root store
// would reject the chain when connecting to host. A chain whose leaf
// cannot even be parsed is untrusted by definition, without an error.
func Untrusted(chainDER [][]byte, host string) (untrusted bool, err error) {
	// A nil pool makes Verify fall back to the system roots, so an error from
	// SystemCertPool needs no separate handling.
	roots, _ := x509.SystemCertPool()

	return untrustedWith(chainDER, host, roots)
}

// Verify checks chainDER for host against roots. A nil roots pool selects the
// system roots. The leaf must carry the server-auth extended key usage, as a
// normal client would require.
func Verify(chainDER [][]byte, host string, roots *x509.CertPool) (err error) {
	return verifyChain(chainDER, host, roots)
}

// verifyChain is the shared verification path behind [Verify] and
// [untrustedWith].
func verifyChain(chainDER [][]byte, host string, roots *x509.CertPool) (err error) {
	if len(chainDER) == 0 {
		err = hqgoerrors.New("invalid input, certificate chain is empty")

		return
	}

	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		err = hqgoerrors.Wrap(err, "parsing leaf certificate")

		return
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

	return
}

// LoadCAPool reads a PEM file and returns its certificates as a root pool.
func LoadCAPool(path string) (pool *x509.CertPool, err error) {
	pemBytes, err := os.ReadFile(path) //nolint:gosec // path is the caller-specified CA file.
	if err != nil {
		err = hqgoerrors.Stack(err)

		return
	}

	pool = x509.NewCertPool()

	if !pool.AppendCertsFromPEM(pemBytes) {
		err = hqgoerrors.New("no certificates parsed from CA certificate file")

		return
	}

	return
}

// untrustedWith reports whether the chain fails verification against the
// given root pool, treating a pool of nil as the system roots.
func untrustedWith(chainDER [][]byte, host string, roots *x509.CertPool) (untrusted bool, err error) {
	if len(chainDER) == 0 {
		err = hqgoerrors.New("invalid input, certificate chain is empty")

		return false, err
	}

	if _, parseErr := x509.ParseCertificate(chainDER[0]); parseErr != nil {
		return true, nil
	}

	if err = verifyChain(chainDER, host, roots); err != nil {
		return true, nil
	}

	return false, nil
}

// Revoked reports whether the leaf certificate has been revoked,
// checking the certificate's OCSP responders first and falling back to its CRL
// distribution points. A responder that is unreachable, empty, or
// inconclusive ("unknown" status) is skipped in favor of the next source;
// only an explicit "revoked" answer reports true.
//
// The context bounds the OCSP and CRL requests. The chain holds the DER
// certificate chain, leaf first, with the issuer second when present.
func Revoked(ctx context.Context, chainDER [][]byte) (revoked bool, err error) {
	if len(chainDER) == 0 {
		err = hqgoerrors.New("invalid input, certificate chain is empty")

		return false, err
	}

	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		err = hqgoerrors.Wrap(err, "parsing leaf certificate")

		return false, err
	}

	issuer := leaf

	if len(chainDER) > 1 {
		issuer, err = x509.ParseCertificate(chainDER[1])
		if err != nil {
			err = hqgoerrors.Wrap(err, "parsing issuer certificate")

			return false, err
		}
	}

	client := &http.Client{
		Timeout: revocationTimeout,
	}

	for _, url := range leaf.OCSPServer {
		var status int

		status, ocspErr := fetchOCSPStatus(ctx, client, leaf, issuer, url)
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
		revoked, crlErr := crlRevokes(ctx, client, leaf, url)
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
func fetchOCSPStatus(ctx context.Context, client *http.Client, leaf, issuer *x509.Certificate, url string) (status int, err error) {
	request, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return ocsp.Unknown, hqgoerrors.Wrap(err, "creating OCSP request")
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(request))
	if err != nil {
		return ocsp.Unknown, hqgoerrors.Wrapf(err, "building OCSP request for %q", url)
	}

	httpRequest.Header.Set("Content-Type", "application/ocsp-request")

	response, err := client.Do(httpRequest)
	if err != nil {
		return ocsp.Unknown, hqgoerrors.Wrapf(err, "posting OCSP request to %q", url)
	}

	defer func() {
		_ = response.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxRevocationBody))
	if err != nil {
		return ocsp.Unknown, hqgoerrors.Wrap(err, "reading OCSP response")
	}

	parsed, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return ocsp.Unknown, hqgoerrors.Wrapf(err, "parsing OCSP response from %q", url)
	}

	return parsed.Status, nil
}

// crlRevokes checks whether a CRL distribution point revokes the leaf.
func crlRevokes(ctx context.Context, client *http.Client, leaf *x509.Certificate, url string) (revoked bool, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, hqgoerrors.Wrapf(err, "building CRL request for %q", url)
	}

	response, err := client.Do(request)
	if err != nil {
		return false, hqgoerrors.Wrapf(err, "fetching CRL from %q", url)
	}

	defer func() {
		_ = response.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxRevocationBody))
	if err != nil {
		return false, hqgoerrors.Wrap(err, "reading CRL")
	}

	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return false, hqgoerrors.Wrapf(err, "parsing CRL from %q", url)
	}

	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}
