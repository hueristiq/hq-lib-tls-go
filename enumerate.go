package tls

import (
	"context"
	"sort"
	"sync"

	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
	hqgotlsclient "github.com/hueristiq/hq-lib-tls-go/client"
)

// EnumerateVersions reports the TLS versions the server accepts. It probes
// once per version with the version pinned as both minimum and maximum, using
// the client's configured config, timeout, SNI, and proxy.
//
// A version the server rejects is skipped rather than reported as an error;
// only a canceled context stops the enumeration.
func (p *Client) EnumerateVersions(ctx context.Context, host string) (versions []uint16, err error) {
	for _, candidate := range hqgotlsclient.SupportedVersions() {
		if err := ctx.Err(); err != nil {
			return versions, err
		}

		prober := p.cloneWith(func(config *hqgotlsclient.Config) {
			config.MinVersion = candidate.ID
			config.MaxVersion = candidate.ID
			config.CipherSuites = nil
		})

		result, probeErr := prober.Inspect(ctx, host)
		if probeErr != nil || result.TLSVersion != candidate.ID {
			continue
		}

		versions = append(versions, candidate.ID)
	}

	return versions, nil
}

// EnumerateCipherSuites reports the cipher suites the server accepts. It
// probes once per implemented suite, clamping the version range to the
// versions the suite is defined for. concurrency bounds the number of probes
// in flight; values below one are treated as one.
//
// A suite the server rejects is skipped rather than reported as an error; only
// a canceled context stops the enumeration.
func (p *Client) EnumerateCipherSuites(ctx context.Context, host string, concurrency int) (suites []uint16, err error) {
	candidates := hqgotlsciphers.Implemented()

	if len(candidates) == 0 {
		return nil, nil
	}

	if concurrency < 1 {
		concurrency = 1
	}

	if concurrency > len(candidates) {
		concurrency = len(candidates)
	}

	work := make(chan *hqgotlsciphers.Suite)
	collected := make(chan uint16, len(candidates))

	waitGroup := &sync.WaitGroup{}

	for range concurrency {
		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			for suite := range work {
				if ctx.Err() != nil {
					return
				}

				version, ok := suiteVersionWithin(suite, 0, 0)
				if !ok {
					continue
				}

				prober := p.cloneWith(func(config *hqgotlsclient.Config) {
					config.CipherSuites = []uint16{suite.ID}
					config.AllowExportCipherSuites = suite.Export
					config.MinVersion = version
					config.MaxVersion = version
				})

				result, probeErr := prober.Inspect(ctx, host)
				if probeErr != nil || result.CipherSuite != suite.ID {
					continue
				}

				collected <- suite.ID
			}
		}()
	}

feed:
	for i := range candidates {
		select {
		case work <- &candidates[i]:
		case <-ctx.Done():
			break feed
		}
	}

	close(work)
	waitGroup.Wait()
	close(collected)

	for suite := range collected {
		suites = append(suites, suite)
	}

	sort.Slice(suites, func(i, j int) bool {
		return suites[i] < suites[j]
	})

	err = ctx.Err()

	return suites, err
}

// suiteVersionWithin returns the highest version the suite supports within
// the configured range.
func suiteVersionWithin(suite *hqgotlsciphers.Suite, minVersion, maxVersion uint16) (version uint16, ok bool) {
	for _, candidate := range suite.Versions {
		if minVersion != 0 && candidate < minVersion {
			continue
		}

		if maxVersion != 0 && candidate > maxVersion {
			continue
		}

		if candidate > version {
			version = candidate
		}
	}

	return version, version != 0
}
