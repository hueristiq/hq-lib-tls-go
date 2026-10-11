package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"os/exec"
	"strings"
)

// versionNames maps OpenSSL's session protocol names to TLS version IDs.
var versionNames = map[string]uint16{
	"SSLv3":   sslVersion30,
	"TLSv1":   tls.VersionTLS10,
	"TLSv1.1": tls.VersionTLS11,
	"TLSv1.2": tls.VersionTLS12,
	"TLSv1.3": tls.VersionTLS13,
}

// cipherSuiteIDs maps cipher suite names to their IDs, covering both the
// secure and the legacy (insecure) sets. The standard library's IANA-style
// names (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) are normalized into the
// OpenSSL spellings s_client prints (ECDHE-ECDSA-AES128-GCM-SHA256),
// including the CBC-less variant OpenSSL uses for CBC suites.
func cipherSuiteIDs() (ids map[string]uint16) {
	suites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)

	ids = make(map[string]uint16, len(suites)*2)

	for _, suite := range suites {
		for _, name := range opensslNames(suite.Name) {
			ids[name] = suite.ID
		}
	}

	return ids
}

// opensslNames renders a standard library cipher suite name in the
// spellings OpenSSL's s_client prints.
//
// Parameters:
//   - name (string): the IANA-style suite name.
//
// Returns:
//   - names ([]string): the OpenSSL spellings.
func opensslNames(name string) (names []string) {
	name = strings.TrimPrefix(name, "TLS_")
	name = strings.Replace(name, "_WITH_", "-", 1)
	name = strings.ReplaceAll(name, "_", "-")

	// OpenSSL joins algorithm and size without a separator:
	// "AES-128" is "AES128", and 3DES-EDE is "DES-CBC3".
	for _, algorithm := range []string{"AES", "CAMELLIA", "ARIA"} {
		for _, size := range []string{"128", "256"} {
			name = strings.Replace(name, algorithm+"-"+size, algorithm+size, 1)
		}
	}

	name = strings.Replace(name, "3DES-EDE", "DES-CBC3", 1)

	names = append(names, name)

	if strings.Contains(name, "-CBC-") {
		names = append(names, strings.Replace(name, "-CBC-", "-", 1))
	}

	return names
}

// probeWithOpenSSL probes host by shelling out to the OpenSSL binary
// (s_client) and parsing its session output. The OpenSSL binary must be
// installed and either on PATH or pointed to by [WithOpenSSLBinary].
//
// Parameters:
//   - ctx (context.Context): the context bounding the operation.
//   - host (string): the hostname or IP (without port).
//   - address (string): the dial address (host:port).
//
// Returns:
//   - result (Result): the probe outcome.
//   - err (error): non-nil when OpenSSL is missing or produces no parseable output.
func (p *Prober) probeWithOpenSSL(ctx context.Context, host, address string) (result Result, err error) {
	result.Mode = ModeOpenSSL

	args := []string{"s_client", "-connect", address}

	serverName := p.options.ServerName

	if serverName == "" {
		serverName = host
	}

	if serverName != "" {
		args = append(args, "-servername", serverName)
	}

	args = append(args, "-prexit", "-showcerts")

	command := exec.CommandContext(ctx, p.options.OpenSSLBinary, args...) //nolint:gosec // G204: the OpenSSL binary path is an explicit user option, by design.

	var output bytes.Buffer

	command.Stdout = &output
	command.Stderr = &output

	// s_client commonly exits non-zero even after a perfectly good session
	// (for example when the connection is closed), so the exit status is
	// not authoritative; the parsed session output is.
	_ = command.Run()

	session := output.String()

	if err = parseOpenSSLOutput(session, address, &result); err != nil {
		err = fmt.Errorf("probeWithOpenSSL: %w", err)

		return result, err
	}

	result.IP = remoteIPFromOpenSSL(session)

	return result, nil
}

// parseOpenSSLOutput extracts the negotiated protocol, cipher, ALPN, and
// certificate chain from an s_client session dump.
//
// Parameters:
//   - output (string): the s_client output.
//   - address (string): the dial address, for error messages.
//   - result (*Result): the result to fill.
//
// Returns:
//   - err (error): non-nil when the output lacks a protocol line.
func parseOpenSSLOutput(output, address string, result *Result) (err error) {
	if !strings.Contains(output, "Protocol:") && !strings.Contains(output, "Protocol ") {
		err = fmt.Errorf("probe.parseOpenSSLOutput: no session in OpenSSL output for %s (is the OpenSSL binary available?)", address)

		return err
	}

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)

		switch {
		case strings.HasPrefix(line, "Protocol:"):
			if version, ok := versionNames[fields[1]]; ok {
				result.TLSVersion = version
			}
		case strings.HasPrefix(line, "Protocol "):
			if len(fields) >= 3 {
				if version, ok := versionNames[fields[2]]; ok {
					result.TLSVersion = version
				}
			}
		case strings.HasPrefix(line, "New,"):
			// OpenSSL 3 renders the cipher as
			// "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384".
			if _, cipher, found := strings.Cut(line, "Cipher is "); found {
				if id, ok := cipherSuiteIDs()[strings.TrimSpace(cipher)]; ok {
					result.CipherSuite = id
				}
			}
		case len(fields) >= 3 && fields[0] == "Cipher":
			// The SSL-Session block renders it as
			// "Cipher    : ECDHE-ECDSA-AES128-GCM-SHA256".
			if id, ok := cipherSuiteIDs()[fields[2]]; ok {
				result.CipherSuite = id
			}
		case strings.HasPrefix(line, "ALPN protocol:"):
			if len(fields) >= 3 {
				result.ALPN = fields[2]
			}
		}
	}

	rest := output

	for {
		block, remainder := pem.Decode([]byte(rest))

		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			result.Certificates = append(result.Certificates, block.Bytes)
		}

		rest = string(remainder)
	}

	return nil
}

// remoteIPFromOpenSSL extracts the connected IP from an s_client session
// dump ("Connecting to ..." line). It is best-effort: the line carries the
// target address, not necessarily the IP the connection used.
//
// Parameters:
//   - output (string): the s_client output.
//
// Returns:
//   - ip (string): the IP, or an empty string.
func remoteIPFromOpenSSL(output string) (ip string) {
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "Connecting to ") {
			continue
		}

		fields := strings.Fields(line)

		if len(fields) < 3 {
			break
		}

		ip = fields[len(fields)-1]

		if host, _, splitErr := strings.Cut(ip, ":"); splitErr {
			ip = host
		}

		break
	}

	return ip
}
