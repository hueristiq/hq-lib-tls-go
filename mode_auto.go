package tls

import (
	"context"
)

// inspectWithAuto inspects host with zcrypto first and falls back to the
// standard library when zcrypto cannot establish the connection or
// complete the handshake, maximizing coverage across old and unusual
// servers. The result's Mode records which dialer actually succeeded.
//
// Parameters:
//   - ctx (context.Context): the context bounding the operation.
//   - host (string): the hostname or IP (without port).
//   - address (string): the dial address (host:port).
//
// Returns:
//   - result (Result): the inspection outcome.
//   - err (error): non-nil when neither mode could establish a connection.
func (p *Client) inspectWithAuto(ctx context.Context, host, address string) (result Result, err error) {
	result, err = p.inspectWithZTLS(ctx, host, address)

	if err == nil && result.Error == nil {
		return result, nil
	}

	result, err = p.inspectWithCTLS(ctx, host, address)
	if err != nil {
		return result, err
	}

	return result, nil
}
