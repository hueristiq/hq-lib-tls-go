package tls

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"
)

// JARM probes are ten crafted ClientHellos sent over raw TCP. The server's
// ServerHello responses are parsed and compressed into a 62-character fuzzy
// hash, without completing any handshake.

const (
	// jarmEmptyHash is the JARM result when every probe timed out.
	jarmEmptyHash = "00000000000000000000000000000000000000000000000000000000000000"
	// jarmReadSize is the number of response bytes requested per probe.
	jarmReadSize = 1484
)

// jarmGreaseValues are the reserved GREASE values a client may insert.
var jarmGreaseValues = []uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

// jarmAllCiphers is the cipher list sent by the "ALL" probes.
var jarmAllCiphers = []uint16{
	0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b,
	0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a,
	0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024,
	0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301,
	0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028,
	0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304,
	0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0,
	0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba,
	0x0084, 0x00c0, 0x0007, 0x0004, 0x0005,
}

// jarmNo13Ciphers is the cipher list sent by the "NO1.3" probes: the full
// list minus the TLS 1.3 suites.
var jarmNo13Ciphers = func() (ciphers []uint16) {
	for _, cipher := range jarmAllCiphers {
		switch cipher {
		case 0x1301, 0x1302, 0x1303, 0x1304, 0x1305:
			continue
		}

		ciphers = append(ciphers, cipher)
	}

	return ciphers
}()

// jarmALPNProtocols is the ALPN list sent by the standard probes, weakest
// to strongest.
var jarmALPNProtocols = []string{
	"http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3",
	"h2", "h2c", "hq",
}

// jarmRareALPNProtocols omits h2 and http/1.1 from the standard list.
var jarmRareALPNProtocols = []string{
	"http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq",
}

// jarmProbeParameters describes one of the ten ClientHello probes.
//
// Fields:
//   - version (string): "TLS_1.1", "TLS_1.2", or "TLS_1.3".
//   - ciphers (string): "ALL" or "NO1.3".
//   - cipherOrder (string): the cipher order munging: FORWARD, REVERSE,
//     TOP_HALF, BOTTOM_HALF, or MIDDLE_OUT.
//   - grease (bool): insert GREASE values into ciphers and extensions.
//   - rareALPN (bool): use the reduced ALPN list.
//   - supportedVersions (string): "1.2_SUPPORT", "NO_SUPPORT", or
//     "1.3_SUPPORT" — controls the supported_versions extension.
//   - alpnOrder (string): the ALPN order munging: FORWARD or REVERSE.
type jarmProbeParameters struct {
	version           string
	ciphers           string
	cipherOrder       string
	grease            bool
	rareALPN          bool
	supportedVersions string
	alpnOrder         string
}

// jarmProbes is the ordered list of the ten JARM probes.
var jarmProbes = []jarmProbeParameters{
	{version: "TLS_1.2", ciphers: "ALL", cipherOrder: "FORWARD", supportedVersions: "1.2_SUPPORT", alpnOrder: "REVERSE"},
	{version: "TLS_1.2", ciphers: "ALL", cipherOrder: "REVERSE", supportedVersions: "1.2_SUPPORT", alpnOrder: "FORWARD"},
	{version: "TLS_1.2", ciphers: "ALL", cipherOrder: "TOP_HALF", supportedVersions: "NO_SUPPORT", alpnOrder: "FORWARD"},
	{version: "TLS_1.2", ciphers: "ALL", cipherOrder: "BOTTOM_HALF", rareALPN: true, supportedVersions: "NO_SUPPORT", alpnOrder: "FORWARD"},
	{version: "TLS_1.2", ciphers: "ALL", cipherOrder: "MIDDLE_OUT", grease: true, rareALPN: true, supportedVersions: "NO_SUPPORT", alpnOrder: "REVERSE"},
	{version: "TLS_1.1", ciphers: "ALL", cipherOrder: "FORWARD", supportedVersions: "NO_SUPPORT", alpnOrder: "FORWARD"},
	{version: "TLS_1.3", ciphers: "ALL", cipherOrder: "FORWARD", supportedVersions: "1.3_SUPPORT", alpnOrder: "REVERSE"},
	{version: "TLS_1.3", ciphers: "ALL", cipherOrder: "REVERSE", supportedVersions: "1.3_SUPPORT", alpnOrder: "FORWARD"},
	{version: "TLS_1.3", ciphers: "NO1.3", cipherOrder: "FORWARD", supportedVersions: "1.3_SUPPORT", alpnOrder: "FORWARD"},
	{version: "TLS_1.3", ciphers: "ALL", cipherOrder: "MIDDLE_OUT", grease: true, supportedVersions: "1.3_SUPPORT", alpnOrder: "REVERSE"},
}

// jarmHello is the parsed ServerHello data of a single JARM probe.
//
// Fields:
//   - cipher (string): the selected cipher as a hex string.
//   - version (string): the selected version as a hex string.
//   - alpn (string): the negotiated ALPN protocol.
//   - extensions (string): the extension type IDs joined by hyphens.
type jarmHello struct {
	cipher     string
	version    string
	alpn       string
	extensions string
}

// JARM computes the JARM fingerprint of host: it sends the ten crafted
// ClientHello probes defined by the JARM specification and fuzzy-hashes
// the servers' responses, without completing any handshake. The host is
// used as the SNI value in every probe.
//
// A timeout on any probe yields the all-zero hash: a partial fingerprint
// would describe the client, not the server. A probe whose connection fails
// contributes empty fields.
//
// Parameters:
//   - ctx (context.Context): the context bounding the operation.
//   - host (string): the target, as hostname, IP, "host:port", or "IP:port".
//
// Returns:
//   - jarm (string): the 62-character JARM fingerprint.
//   - err (error): non-nil when the input is invalid.
func (p *Client) JARM(ctx context.Context, host string) (jarm string, err error) {
	host, port, err := splitHostPort(host)
	if err != nil {
		err = fmt.Errorf("client.JARM: %w", err)

		return "", err
	}

	address := net.JoinHostPort(host, port)

	hellos := make([]jarmHello, 0, len(jarmProbes))

	for _, parameters := range jarmProbes {
		var hello jarmHello

		hello, err = p.sendJARMProbe(ctx, host, address, &parameters)
		if err != nil {
			// A timeout anywhere yields the all-zero hash: a partial
			// fingerprint would describe the client, not the server.
			return jarmEmptyHash, nil
		}

		hellos = append(hellos, hello)
	}

	jarm = jarmHash(hellos)

	return jarm, nil
}

// sendJARMProbe sends one crafted ClientHello and parses the ServerHello
// response.
//
// Parameters:
//   - ctx (context.Context): the context bounding the operation.
//   - host (string): the SNI hostname.
//   - address (string): the dial address.
//   - parameters (*jarmProbeParameters): the probe's parameters.
//
// Returns:
//   - hello (jarmHello): the parsed ServerHello data.
//   - err (error): non-nil when the probe timed out.
func (p *Client) sendJARMProbe(ctx context.Context, host, address string, parameters *jarmProbeParameters) (hello jarmHello, err error) {
	conn, err := p.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		// A failed connection contributes empty fields; only a timeout
		// aborts the whole fingerprint.
		return jarmHello{}, nil
	}

	defer func() {
		_ = conn.Close()
	}()

	if err = conn.SetDeadline(time.Now().Add(p.options.Timeout)); err != nil {
		return jarmHello{}, nil
	}

	packet, err := buildJARMClientHello(host, parameters)
	if err != nil {
		return jarmHello{}, fmt.Errorf("client.sendJARMProbe: building probe: %w", err)
	}

	if _, err = conn.Write(packet); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return jarmHello{}, fmt.Errorf("client.sendJARMProbe: writing probe: %w", err)
		}

		return jarmHello{}, nil
	}

	buffer := make([]byte, jarmReadSize)

	n, err := conn.Read(buffer)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return jarmHello{}, fmt.Errorf("client.sendJARMProbe: reading server response: %w", err)
		}

		return jarmHello{}, nil
	}

	if err = ctx.Err(); err != nil {
		return jarmHello{}, fmt.Errorf("client.sendJARMProbe: context ended: %w", err)
	}

	return parseJARMServerHello(buffer[:n]), nil
}

// buildJARMClientHello assembles a ClientHello record according to the
// JARM specification.
//
// Parameters:
//   - host (string): the SNI hostname.
//   - parameters (*jarmProbeParameters): the probe's parameters.
//
// Returns:
//   - packet ([]byte): the complete TLS record.
func buildJARMClientHello(host string, parameters *jarmProbeParameters) (packet []byte, err error) {
	recordVersion := []byte{0x03, 0x03}

	var clientHello []byte

	switch parameters.version {
	case "TLS_1.1":
		recordVersion = []byte{0x03, 0x01}
		clientHello = []byte{0x03, 0x02}
	case "TLS_1.3":
		recordVersion = []byte{0x03, 0x01}
		clientHello = []byte{0x03, 0x03}
	default:
		clientHello = []byte{0x03, 0x03}
	}

	random, err := randomBytes(rand.Reader, 32)
	if err != nil {
		return nil, err
	}

	clientHello = append(clientHello, random...)

	sessionID, err := randomBytes(rand.Reader, 32)
	if err != nil {
		return nil, err
	}

	clientHello, err = appendLength8(clientHello, len(sessionID))
	if err != nil {
		return nil, err
	}

	clientHello = append(clientHello, sessionID...)

	ciphers := jarmCipherList(parameters)

	if parameters.cipherOrder != "FORWARD" {
		ciphers = jarmMung(ciphers, parameters.cipherOrder)
	}

	if parameters.grease {
		ciphers = append([]uint16{randomGrease(rand.Reader)}, ciphers...)
	}

	clientHello, err = appendLength16(clientHello, len(ciphers)*2)
	if err != nil {
		return nil, err
	}

	for _, cipher := range ciphers {
		clientHello = appendUint16(clientHello, cipher)
	}

	clientHello = append(clientHello, 0x01, 0x00) // compression: one method, null

	extensions, err := buildJARMExtensions(host, parameters)
	if err != nil {
		return nil, err
	}

	clientHello = append(clientHello, extensions...)

	handshake := make([]byte, 1, 1+len(clientHello))
	handshake[0] = 0x01

	handshake, err = appendLength24(handshake, len(clientHello))
	if err != nil {
		return nil, err
	}

	handshake = append(handshake, clientHello...)

	packet = []byte{0x16}
	packet = append(packet, recordVersion...)

	packet, err = appendLength16(packet, len(handshake))
	if err != nil {
		return nil, err
	}

	packet = append(packet, handshake...)

	return packet, nil
}

// buildJARMExtensions assembles the extension block of a JARM ClientHello.
//
// Parameters:
//   - host (string): the SNI hostname.
//   - parameters (*jarmProbeParameters): the probe's parameters.
//
// Returns:
//   - extensions ([]byte): the length-prefixed extension block.
func buildJARMExtensions(host string, parameters *jarmProbeParameters) (extensions []byte, err error) {
	var all []byte

	if parameters.grease {
		all = appendUint16(all, randomGrease(rand.Reader))
		all = appendUint16(all, 0)
	}

	serverName, err := buildJARMServerName(host)
	if err != nil {
		return nil, err
	}

	all = append(all, serverName...)
	all = append(all, []byte{0x00, 0x17, 0x00, 0x00}...)
	all = append(all, []byte{0x00, 0x01, 0x00, 0x01, 0x01}...)
	all = append(all, []byte{0xff, 0x01, 0x00, 0x01, 0x00}...)
	all = append(all, []byte{0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19}...)
	all = append(all, []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}...)
	all = append(all, []byte{0x00, 0x23, 0x00, 0x00}...)

	alpn, err := buildJARMALPN(parameters)
	if err != nil {
		return nil, err
	}

	all = append(all, alpn...)
	all = append(all, []byte{0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01}...)

	keyShare, err := buildJARMKeyShare(parameters.grease)
	if err != nil {
		return nil, err
	}

	all = append(all, keyShare...)
	all = append(all, []byte{0x00, 0x2d, 0x00, 0x02, 0x01, 0x01}...)

	if parameters.version == "TLS_1.3" || parameters.supportedVersions == "1.2_SUPPORT" {
		supportedVersions, err := buildJARMSupportedVersions(parameters)
		if err != nil {
			return nil, err
		}

		all = append(all, supportedVersions...)
	}

	extensions, err = appendLength16(nil, len(all))
	if err != nil {
		return nil, err
	}

	extensions = append(extensions, all...)

	return extensions, nil
}

// buildJARMServerName assembles the server_name (SNI) extension.
//
// Parameters:
//   - host (string): the SNI hostname.
//
// Returns:
//   - extension ([]byte): the extension bytes.
func buildJARMServerName(host string) (extension []byte, err error) {
	sni := []byte(host)

	extension = appendUint16(extension, 0x0000)

	extension, err = appendLength16(extension, len(sni)+5)
	if err != nil {
		return nil, err
	}

	extension, err = appendLength16(extension, len(sni)+3)
	if err != nil {
		return nil, err
	}

	extension = append(extension, 0x00)

	extension, err = appendLength16(extension, len(sni))
	if err != nil {
		return nil, err
	}

	extension = append(extension, sni...)

	return extension, nil
}

// buildJARMALPN assembles the ALPN extension.
//
// Parameters:
//   - parameters (*jarmProbeParameters): the probe's parameters.
//
// Returns:
//   - extension ([]byte): the extension bytes.
func buildJARMALPN(parameters *jarmProbeParameters) (extension []byte, err error) {
	protocols := jarmALPNProtocols

	if parameters.rareALPN {
		protocols = jarmRareALPNProtocols
	}

	if parameters.alpnOrder != "FORWARD" {
		protocols = jarmMung(protocols, parameters.alpnOrder)
	}

	var all []byte

	for _, protocol := range protocols {
		all, err = appendLength8(all, len(protocol))
		if err != nil {
			return nil, err
		}

		all = append(all, protocol...)
	}

	extension = appendUint16(nil, 0x0010)

	extension, err = appendLength16(extension, len(all)+2)
	if err != nil {
		return nil, err
	}

	extension, err = appendLength16(extension, len(all))
	if err != nil {
		return nil, err
	}

	extension = append(extension, all...)

	return extension, nil
}

// buildJARMKeyShare assembles the key_share extension around the X25519
// group with a random key exchange.
//
// Parameters:
//   - grease (bool): prepend a GREASE share.
//
// Returns:
//   - extension ([]byte): the extension bytes.
func buildJARMKeyShare(grease bool) (extension []byte, err error) {
	var share []byte

	if grease {
		share = appendUint16(share, randomGrease(rand.Reader))
		share = appendUint16(share, 0x0001)
		share = append(share, 0x00)
	}

	share = appendUint16(share, 0x001d)
	share = appendUint16(share, 0x0020)

	random, err := randomBytes(rand.Reader, 32)
	if err != nil {
		return nil, err
	}

	share = append(share, random...)

	extension = appendUint16(nil, 0x0033)

	extension, err = appendLength16(extension, len(share)+2)
	if err != nil {
		return nil, err
	}

	extension, err = appendLength16(extension, len(share))
	if err != nil {
		return nil, err
	}

	extension = append(extension, share...)

	return extension, nil
}

// buildJARMSupportedVersions assembles the supported_versions extension.
//
// Parameters:
//   - parameters (*jarmProbeParameters): the probe's parameters.
//
// Returns:
//   - extension ([]byte): the extension bytes.
func buildJARMSupportedVersions(parameters *jarmProbeParameters) (extension []byte, err error) {
	versions := []uint16{0x0301, 0x0302, 0x0303}

	if parameters.supportedVersions == "1.3_SUPPORT" {
		versions = append(versions, 0x0304)
	}

	if parameters.alpnOrder != "FORWARD" {
		versions = jarmMung(versions, parameters.alpnOrder)
	}

	var raw []byte

	if parameters.grease {
		raw = appendUint16(raw, randomGrease(rand.Reader))
	}

	for _, version := range versions {
		raw = appendUint16(raw, version)
	}

	extension = appendUint16(nil, 0x002b)

	extension, err = appendLength16(extension, len(raw)+1)
	if err != nil {
		return nil, err
	}

	extension, err = appendLength8(extension, len(raw))
	if err != nil {
		return nil, err
	}

	extension = append(extension, raw...)

	return extension, nil
}

// jarmCipherList selects the cipher list for a probe.
//
// Parameters:
//   - parameters (*jarmProbeParameters): the probe's parameters.
//
// Returns:
//   - ciphers ([]uint16): the cipher list.
func jarmCipherList(parameters *jarmProbeParameters) (ciphers []uint16) {
	if parameters.ciphers == "NO1.3" {
		return jarmNo13Ciphers
	}

	return jarmAllCiphers
}

// jarmMung reorders items according to one of the JARM order mungings.
//
// Parameters:
//   - items ([]T): the items to reorder.
//   - order (string): FORWARD, REVERSE, BOTTOM_HALF, TOP_HALF, or MIDDLE_OUT.
//
// Returns:
//   - reordered ([]T): the reordered items.
func jarmMung[T any](items []T, order string) (reordered []T) {
	switch order {
	case "REVERSE":
		reordered = make([]T, len(items))

		for i, item := range items {
			reordered[len(items)-1-i] = item
		}
	case "BOTTOM_HALF":
		if len(items)%2 == 1 {
			reordered = items[len(items)/2+1:]
		} else {
			reordered = items[len(items)/2:]
		}
	case "TOP_HALF":
		reordered = jarmMung(jarmMung(items, "REVERSE"), "BOTTOM_HALF")

		if len(items)%2 == 1 {
			reordered = append(append([]T(nil), items[len(items)/2]), reordered...)
		}
	case "MIDDLE_OUT":
		middle := len(items) / 2

		output := make([]T, 0, len(items))

		if len(items)%2 == 1 {
			output = append(output, items[middle])

			for i := 1; i <= middle; i++ {
				output = append(output, items[middle+i], items[middle-i])
			}
		} else {
			for i := 1; i <= middle; i++ {
				output = append(output, items[middle-1+i], items[middle-i])
			}
		}

		reordered = output
	default:
		reordered = items
	}

	return reordered
}

// parseJARMServerHello extracts the selected cipher, version, ALPN, and
// extension types from a captured server flight using the fixed byte
// offsets of the JARM wire format.
//
// Parameters:
//   - data ([]byte): the captured bytes.
//
// Returns:
//   - hello (jarmHello): the parsed fields; empty on unrecognized input.
func parseJARMServerHello(data []byte) (hello jarmHello) {
	if len(data) < 46 || data[0] == 21 || data[0] != 22 || data[5] != 2 {
		return jarmHello{}
	}

	serverHelloLength := int(data[3])<<8 | int(data[4])
	counter := int(data[43])

	if counter+49 > len(data) {
		return jarmHello{}
	}

	hello.cipher = hex.EncodeToString(data[counter+44 : counter+46])
	hello.version = hex.EncodeToString(data[9:11])

	// Servers that answer with a non-standard byte at this offset produce
	// no usable extension block: keep the cipher and version, leave the
	// ALPN and extension fields empty.
	if data[counter+47] == 11 {
		return hello
	}

	if counter+53 <= len(data) && bytes.Equal(data[counter+50:counter+53], []byte{0x0e, 0xac, 0x0b}) {
		return hello
	}

	if len(data) >= 85 && bytes.Equal(data[82:85], []byte{0x0f, 0xf0, 0x0b}) {
		return hello
	}

	if counter+42 >= serverHelloLength {
		return hello
	}

	extensionsLength := int(data[counter+47])<<8 | int(data[counter+48])

	count := 49 + counter
	maximum := extensionsLength + count - 1

	var types []uint16

	var values [][]byte

	// The walk stops at maximum but bounds every read against the buffer, so
	// a complete extension may extend one step past maximum. Truncated data
	// ends the walk with the cipher and version already collected.
	for count < maximum {
		if count+4 > len(data) {
			return hello
		}

		types = append(types, uint16(data[count])<<8|uint16(data[count+1]))

		extensionLength := int(data[count+2])<<8 | int(data[count+3])

		if extensionLength == 0 {
			count += 4

			values = append(values, nil)

			continue
		}

		if count+4+extensionLength > len(data) {
			return hello
		}

		values = append(values, data[count+4:count+4+extensionLength])

		count += extensionLength + 4
	}

	for i, extensionType := range types {
		if extensionType == 0x0010 && len(values[i]) >= 4 {
			hello.alpn = string(values[i][3:])

			break
		}
	}

	parts := make([]string, len(types))

	for i, extensionType := range types {
		parts[i] = fmt.Sprintf("%04x", extensionType)
	}

	hello.extensions = strings.Join(parts, "-")

	return hello
}

// jarmHash compresses the parsed ServerHello data of the ten probes into
// the 62-character JARM fingerprint.
//
// Parameters:
//   - hellos ([]jarmHello): the parsed probes.
//
// Returns:
//   - hash (string): the fingerprint.
func jarmHash(hellos []jarmHello) (hash string) {
	empty := true

	for _, hello := range hellos {
		if hello.cipher != "" || hello.version != "" || hello.alpn != "" || hello.extensions != "" {
			empty = false

			break
		}
	}

	if empty {
		return jarmEmptyHash
	}

	var fuzzy strings.Builder

	var alpnsAndExtensions strings.Builder

	for _, hello := range hellos {
		fuzzy.WriteString(jarmCipherBytes(hello.cipher))
		fuzzy.WriteString(jarmVersionByte(hello.version))

		alpnsAndExtensions.WriteString(hello.alpn)
		alpnsAndExtensions.WriteString(hello.extensions)
	}

	sum := sha256.Sum256([]byte(alpnsAndExtensions.String()))

	fuzzy.WriteString(hex.EncodeToString(sum[:])[:32])

	return fuzzy.String()
}

// jarmCipherBytes maps the selected cipher to its two-character fuzzy
// index: the position of the cipher in the ordered probe list, or "00"
// when no cipher was selected, or "47" when the cipher is not in the list
// (the value beyond the last index).
//
// Parameters:
//   - cipher (string): the selected cipher as a hex string.
//
// Returns:
//   - fuzzy (string): the two-character fuzzy value.
func jarmCipherBytes(cipher string) (fuzzy string) {
	if cipher == "" {
		return "00"
	}

	for index, candidate := range jarmAllCiphers {
		if cipher == fmt.Sprintf("%04x", candidate) {
			return fmt.Sprintf("%02x", index+1)
		}
	}

	return "47"
}

// jarmVersionByte maps the selected version to its single-character fuzzy
// value: "a" through "f" for the minor version 0 through 5, or "0" when
// absent or unrecognized.
//
// Parameters:
//   - version (string): the selected version as a hex string.
//
// Returns:
//   - fuzzy (string): the single-character fuzzy value.
func jarmVersionByte(version string) (fuzzy string) {
	if len(version) != 4 {
		return "0"
	}

	options := "abcdef"

	minor := version[3] - '0'

	if minor > 5 {
		return "0"
	}

	return options[minor : minor+1]
}

// randomGrease picks a random GREASE value.
//
// Parameters:
//   - reader (io.Reader): the entropy source; production uses crypto/rand.Reader.
//
// Returns:
//   - grease (uint16): the GREASE value.
func randomGrease(reader io.Reader) (grease uint16) {
	index, err := rand.Int(reader, big.NewInt(int64(len(jarmGreaseValues))))
	if err != nil {
		// An entropy failure is unrecoverable here; the first GREASE value is
		// a well-formed placeholder.
		return 0x0a0a
	}

	return jarmGreaseValues[index.Int64()]
}

// randomBytes returns count cryptographically random bytes from reader.
//
// Parameters:
//   - reader (io.Reader): the entropy source; production uses crypto/rand.Reader.
//   - count (int): the number of bytes.
//
// Returns:
//   - raw ([]byte): the random bytes.
//   - err (error): non-nil when the entropy source fails.
func randomBytes(reader io.Reader, count int) (raw []byte, err error) {
	raw = make([]byte, count)

	if _, err = io.ReadFull(reader, raw); err != nil {
		return nil, fmt.Errorf("client.randomBytes: reading random bytes: %w", err)
	}

	return raw, nil
}

// appendLength8 appends length as a single byte, reporting an overflow when it does
// not fit. Every caller feeds lengths of buffers built in-memory a moment
// earlier, so the bounds are always satisfiable.
//
// Parameters:
//   - raw ([]byte): the destination buffer.
//   - length (int): the value to append.
//
// Returns:
//   - extended ([]byte): the extended buffer.
//   - err (error): non-nil when length is negative or overflows the encoding width.
func appendLength8(raw []byte, length int) (extended []byte, err error) {
	if length < 0 || length > 0xFF {
		return nil, fmt.Errorf("client.appendLength8: length %d does not fit in one byte", length)
	}

	return append(raw, byte(length)), nil
}

// appendLength16 appends length as two big-endian bytes, reporting an
// overflow when it does not fit.
//
// Parameters:
//   - raw ([]byte): the destination buffer.
//   - length (int): the value to append.
//
// Returns:
//   - extended ([]byte): the extended buffer.
//   - err (error): non-nil when length is negative or overflows the encoding width.
func appendLength16(raw []byte, length int) (extended []byte, err error) {
	if length < 0 || length > 0xFFFF {
		return nil, fmt.Errorf("client.appendLength16: length %d does not fit in two bytes", length)
	}

	return appendUint16(raw, uint16(length)), nil
}

// appendLength24 appends length as three big-endian bytes and reports values
// that do not fit.
//
// Parameters:
//   - raw ([]byte): the destination buffer.
//   - length (int): the value to append.
//
// Returns:
//   - extended ([]byte): the extended buffer.
//   - err (error): non-nil when length is negative or overflows the encoding width.
func appendLength24(raw []byte, length int) (extended []byte, err error) {
	if length < 0 || length > 0xFFFFFF {
		return nil, fmt.Errorf("client.appendLength24: length %d does not fit in three bytes", length)
	}

	return append(raw, byte(length>>16), byte(length>>8), byte(length)), nil //nolint:gosec // The range check bounds every converted byte to 0xff.
}

// appendUint16 appends value in big-endian order.
//
// Parameters:
//   - raw ([]byte): the destination buffer.
//   - value (uint16): the value to append.
//
// Returns:
//   - extended ([]byte): the extended buffer.
func appendUint16(raw []byte, value uint16) (extended []byte) {
	raw = append(raw, byte(value>>8), byte(value&0xFF))

	return raw
}
