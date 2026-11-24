package tls

import (
	"context"

	hqgotlsfingerprint "github.com/hueristiq/hq-lib-tls-go/fingerprint"
)

// JARM computes the JARM fingerprint of host using the client's dialer,
// timeout, and proxy settings.
func (p *Client) JARM(ctx context.Context, host string) (jarm string, err error) {
	return hqgotlsfingerprint.JARM(ctx, p.dialer, host, p.options.Timeout)
}
