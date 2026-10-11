package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// This file is a faithful port of the JARM fingerprint specification
// (github.com/salesforce/jarm, BSD 3-Clause): ten crafted ClientHello
// probes are sent over raw TCP, the servers' ServerHello responses are
// parsed, and the collected fields are compressed into a 62-character
// fuzzy hash.

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
// A timeout on any probe yields the all-zero hash, as in the reference
// implementation. A probe whose connection fails contributes empty fields.
//
// Parameters:
//   - ctx (context.Context): the context bounding the operation.
//   - host (string): the target, as hostname, IP, "host:port", or "IP:port".
//
// Returns:
//   - jarm (string): the 62-character JARM fingerprint.
//   - err (error): non-nil when the input is invalid.
func (p *Prober) JARM(ctx context.Context, host string) (jarm string, err error) {
	host, port, err := splitHostPort(host)
	if err != nil {
		err = fmt.Errorf("probe.JARM: %w", err)

		return "", err
	}

	address := net.JoinHostPort(host, port)

	hellos := make([]jarmHello, 0, len(jarmProbes))

	for _, parameters := range jarmProbes {
		var hello jarmHello

		hello, err = p.sendJARMProbe(ctx, host, address, &parameters)
		if err != nil {
			// A timeout anywhere yields the all-zero hash, per the
			// reference implementation.
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
func (p *Prober) sendJARMProbe(ctx context.Context, host, address string, parameters *jarmProbeParameters) (hello jarmHello, err error) {
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

	packet := buildJARMClientHello(host, parameters)

	if _, err = conn.Write(packet); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return jarmHello{}, fmt.Errorf("probe.sendJARMProbe: writing probe: %w", err)
		}

		return jarmHello{}, nil
	}

	buffer := make([]byte, jarmReadSize)

	n, err := conn.Read(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return jarmHello{}, fmt.Errorf("probe.sendJARMProbe: reading server response: %w", err)
		}

		return jarmHello{}, nil
	}

	if err = ctx.Err(); err != nil {
		return jarmHello{}, fmt.Errorf("probe.sendJARMProbe: context ended: %w", err)
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
func buildJARMClientHello(host string, parameters *jarmProbeParameters) (packet []byte) {
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

	clientHello = append(clientHello, randomBytes(32)...)

	sessionID := randomBytes(32)

	clientHello = appendLength8(clientHello, len(sessionID))
	clientHello = append(clientHello, sessionID...)

	ciphers := jarmCipherList(parameters)

	if parameters.cipherOrder != "FORWARD" {
		ciphers = jarmMung(ciphers, parameters.cipherOrder)
	}

	if parameters.grease {
		ciphers = append([]uint16{randomGrease()}, ciphers...)
	}

	clientHello = appendLength16(clientHello, len(ciphers)*2)

	for _, cipher := range ciphers {
		clientHello = appendUint16(clientHello, cipher)
	}

	clientHello = append(clientHello, 0x01, 0x00) // compression: one method, null

	clientHello = append(clientHello, buildJARMExtensions(host, parameters)...)

	handshake := []byte{0x01}
	handshake = appendLength24(handshake, len(clientHello))
	handshake = append(handshake, clientHello...)

	packet = []byte{0x16}
	packet = append(packet, recordVersion...)
	packet = appendLength16(packet, len(handshake))
	packet = append(packet, handshake...)

	return packet
}

// buildJARMExtensions assembles the extension block of a JARM ClientHello.
//
// Parameters:
//   - host (string): the SNI hostname.
//   - parameters (*jarmProbeParameters): the probe's parameters.
//
// Returns:
//   - extensions ([]byte): the length-prefixed extension block.
func buildJARMExtensions(host string, parameters *jarmProbeParameters) (extensions []byte) {
	var all []byte

	if parameters.grease {
		all = appendUint16(all, randomGrease())
		all = appendUint16(all, 0)
	}

	// server_name
	all = append(all, buildJARMServerName(host)...)

	// extended_master_secret
	all = append(all, []byte{0x00, 0x17, 0x00, 0x00}...)

	// max_fragment_length
	all = append(all, []byte{0x00, 0x01, 0x00, 0x01, 0x01}...)

	// renegotiation_info
	all = append(all, []byte{0xff, 0x01, 0x00, 0x01, 0x00}...)

	// supported_groups
	all = append(all, []byte{0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19}...)

	// ec_point_formats
	all = append(all, []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}...)

	// session_ticket
	all = append(all, []byte{0x00, 0x23, 0x00, 0x00}...)

	// application_layer_protocol_negotiation
	all = append(all, buildJARMALPN(parameters)...)

	// signature_algorithms
	all = append(all, []byte{0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01}...)

	// key_share
	all = append(all, buildJARMKeyShare(parameters.grease)...)

	// psk_key_exchange_modes
	all = append(all, []byte{0x00, 0x2d, 0x00, 0x02, 0x01, 0x01}...)

	// supported_versions
	if parameters.version == "TLS_1.3" || parameters.supportedVersions == "1.2_SUPPORT" {
		all = append(all, buildJARMSupportedVersions(parameters)...)
	}

	extensions = appendLength16(nil, len(all))
	extensions = append(extensions, all...)

	return extensions
}

// buildJARMServerName assembles the server_name (SNI) extension.
//
// Parameters:
//   - host (string): the SNI hostname.
//
// Returns:
//   - extension ([]byte): the extension bytes.
func buildJARMServerName(host string) (extension []byte) {
	sni := []byte(host)

	extension = appendUint16(extension, 0x0000)
	extension = appendLength16(extension, len(sni)+5)
	extension = appendLength16(extension, len(sni)+3)
	extension = append(extension, 0x00)
	extension = appendLength16(extension, len(sni))
	extension = append(extension, sni...)

	return extension
}

// buildJARMALPN assembles the ALPN extension.
//
// Parameters:
//   - parameters (*jarmProbeParameters): the probe's parameters.
//
// Returns:
//   - extension ([]byte): the extension bytes.
func buildJARMALPN(parameters *jarmProbeParameters) (extension []byte) {
	protocols := jarmALPNProtocols

	if parameters.rareALPN {
		protocols = jarmRareALPNProtocols
	}

	if parameters.alpnOrder != "FORWARD" {
		protocols = jarmMung(protocols, parameters.alpnOrder)
	}

	var all []byte

	for _, protocol := range protocols {
		all = appendLength8(all, len(protocol))
		all = append(all, protocol...)
	}

	extension = appendUint16(nil, 0x0010)
	extension = appendLength16(extension, len(all)+2)
	extension = appendLength16(extension, len(all))
	extension = append(extension, all...)

	return extension
}

// buildJARMKeyShare assembles the key_share extension around the X25519
// group with a random key exchange.
//
// Parameters:
//   - grease (bool): prepend a GREASE share.
//
// Returns:
//   - extension ([]byte): the extension bytes.
func buildJARMKeyShare(grease bool) (extension []byte) {
	var share []byte

	if grease {
		share = appendUint16(share, randomGrease())
		share = appendUint16(share, 0x0001)
		share = append(share, 0x00)
	}

	share = appendUint16(share, 0x001d)
	share = appendUint16(share, 0x0020)
	share = append(share, randomBytes(32)...)

	extension = appendUint16(nil, 0x0033)
	extension = appendLength16(extension, len(share)+2)
	extension = appendLength16(extension, len(share))
	extension = append(extension, share...)

	return extension
}

// buildJARMSupportedVersions assembles the supported_versions extension.
//
// Parameters:
//   - parameters (*jarmProbeParameters): the probe's parameters.
//
// Returns:
//   - extension ([]byte): the extension bytes.
func buildJARMSupportedVersions(parameters *jarmProbeParameters) (extension []byte) {
	versions := []uint16{0x0301, 0x0302, 0x0303}

	if parameters.supportedVersions == "1.3_SUPPORT" {
		versions = append(versions, 0x0304)
	}

	if parameters.alpnOrder != "FORWARD" {
		versions = jarmMung(versions, parameters.alpnOrder)
	}

	var raw []byte

	if parameters.grease {
		raw = appendUint16(raw, randomGrease())
	}

	for _, version := range versions {
		raw = appendUint16(raw, version)
	}

	extension = appendUint16(nil, 0x002b)
	extension = appendLength16(extension, len(raw)+1)
	extension = appendLength8(extension, len(raw))
	extension = append(extension, raw...)

	return extension
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
// extension types from a captured server flight, following the reference
// implementation's byte offsets and edge-case handling.
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

	// The edge-case exits of the reference implementation: the extension
	// block is skipped, leaving the ALPN and extension fields empty.
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

	// The reference walks while count < maximum but bounds every read
	// against the buffer, so a walk may overshoot maximum by one complete
	// extension. Truncated data ends the walk with empty fields, exactly
	// as the reference's IndexError fallback does.
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
// (as the reference implementation yields when its loop exhausts).
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
// Returns:
//   - grease (uint16): the GREASE value.
func randomGrease() (grease uint16) {
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(jarmGreaseValues))))
	if err != nil {
		// crypto/rand failure is unrecoverable; the zero value is a
		// well-formed GREASE placeholder.
		return 0x0a0a
	}

	return jarmGreaseValues[index.Int64()]
}

// randomBytes returns count cryptographically random bytes. A failure of
// crypto/rand is unrecoverable, so it panics.
//
// Parameters:
//   - count (int): the number of bytes.
//
// Returns:
//   - raw ([]byte): the random bytes.
func randomBytes(count int) (raw []byte) {
	raw = make([]byte, count)

	if _, err := rand.Read(raw); err != nil {
		panic(fmt.Sprintf("probe.randomBytes: reading random bytes: %v", err))
	}

	return raw
}

// appendLength8 appends length as a single byte, panicking when it does
// not fit. Every caller feeds lengths of buffers built in-memory a moment
// earlier, so the bounds are always satisfiable.
//
// Parameters:
//   - raw ([]byte): the destination buffer.
//   - length (int): the value to append.
//
// Returns:
//   - extended ([]byte): the extended buffer.
func appendLength8(raw []byte, length int) (extended []byte) {
	if length < 0 || length > 0xFF {
		panic(fmt.Sprintf("probe.appendLength8: length %d does not fit in one byte", length))
	}

	return append(raw, byte(length))
}

// appendLength16 appends length as two big-endian bytes, panicking when it
// does not fit.
//
// Parameters:
//   - raw ([]byte): the destination buffer.
//   - length (int): the value to append.
//
// Returns:
//   - extended ([]byte): the extended buffer.
func appendLength16(raw []byte, length int) (extended []byte) {
	if length < 0 || length > 0xFFFF {
		panic(fmt.Sprintf("probe.appendLength16: length %d does not fit in two bytes", length))
	}

	return appendUint16(raw, uint16(length))
}

// appendLength24 appends length as three big-endian bytes, panicking when
// it does not fit.
//
// Parameters:
//   - raw ([]byte): the destination buffer.
//   - length (int): the value to append.
//
// Returns:
//   - extended ([]byte): the extended buffer.
func appendLength24(raw []byte, length int) (extended []byte) {
	if length < 0 || length > 0xFFFFFF {
		panic(fmt.Sprintf("probe.appendLength24: length %d does not fit in three bytes", length))
	}

	return append(raw, byte(length>>16), byte(length>>8), byte(length)) //nolint:gosec // G115: guarded by the bounds check above.
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
