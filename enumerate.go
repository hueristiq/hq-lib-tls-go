package tls

import (
	"context"
	"crypto/tls"
	"sort"
	"sync"
)

// EnumerateVersions reports the TLS versions the server accepts. It probes
// once per version with the version pinned as both minimum and maximum, using
// the client's configured mode, timeout, SNI, and proxy.
//
// A version the server rejects is skipped rather than reported as an error;
// only a canceled context stops the enumeration.
//
// Parameters:
//   - ctx (context.Context): the context bounding the probes.
//   - host (string): the target, as accepted by [Client.Inspect].
//
// Returns:
//   - versions ([]uint16): the accepted version IDs, ascending.
//   - err (error): non-nil only when ctx is canceled.
func (p *Client) EnumerateVersions(ctx context.Context, host string) (versions []uint16, err error) {
	candidates := []uint16{
		sslVersion30,
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
		tls.VersionTLS13,
	}

	for _, version := range candidates {
		if err := ctx.Err(); err != nil {
			return versions, err
		}

		prober := p.cloneWith(func(opts *Options) {
			opts.MinVersion = version
			opts.MaxVersion = version
		})

		result, probeErr := prober.Inspect(ctx, host)
		if probeErr != nil || result.Error != nil || result.TLSVersion != version {
			continue
		}

		versions = append(versions, version)
	}

	return
}

// EnumerateCipherSuites reports the cipher suites the server accepts. It
// probes once per suite from the library's cipher classification, using the
// client's configured mode, timeout, SNI, and proxy. concurrency bounds the
// number of probes in flight; values below one are treated as one.
//
// A suite the server rejects is skipped rather than reported as an error; only
// a canceled context stops the enumeration.
//
// Parameters:
//   - ctx (context.Context): the context bounding the probes.
//   - host (string): the target, as accepted by [Client.Inspect].
//   - concurrency (int): the maximum number of simultaneous probes.
//
// Returns:
//   - suites ([]uint16): the accepted cipher suite IDs, ascending.
//   - err (error): non-nil only when ctx is canceled.
func (p *Client) EnumerateCipherSuites(ctx context.Context, host string, concurrency int) (suites []uint16, err error) {
	candidates := CipherSuitesBySecurity(CipherSecurityInsecure)

	if concurrency < 1 {
		concurrency = 1
	}

	if concurrency > len(candidates) {
		concurrency = len(candidates)
	}

	if len(candidates) == 0 {
		return
	}

	work := make(chan uint16)
	collected := make(chan uint16, len(candidates))

	wg := &sync.WaitGroup{}

	for range concurrency {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for suite := range work {
				if ctx.Err() != nil {
					return
				}

				prober := p.cloneWith(func(opts *Options) {
					opts.CipherSuites = []uint16{suite}
				})

				result, probeErr := prober.Inspect(ctx, host)
				if probeErr != nil || result.Error != nil || result.CipherSuite != suite {
					continue
				}

				collected <- suite
			}
		}()
	}

feed:
	for _, suite := range candidates {
		select {
		case work <- suite:
		case <-ctx.Done():
			break feed
		}
	}

	close(work)
	wg.Wait()
	close(collected)

	for suite := range collected {
		suites = append(suites, suite)
	}

	sort.Slice(suites, func(i, j int) bool {
		return suites[i] < suites[j]
	})

	err = ctx.Err()

	return
}

// cloneWith returns a client sharing the original dialer but with a copy of
// the options updated by update.
//
// Parameters:
//   - update (func(*Options)): the option mutation.
//
// Returns:
//   - client (*Client): the derived client.
func (p *Client) cloneWith(update func(*Options)) (client *Client) {
	opts := p.options

	update(&opts)

	client = &Client{
		options: opts,
		dialer:  p.dialer,
	}

	return
}
