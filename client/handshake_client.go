package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"time"

	hqgotlsclientkeys "github.com/hueristiq/hq-lib-tls-go/client/internal/keys"
	"github.com/hueristiq/hq-lib-tls-go/client/internal/message"
	"github.com/hueristiq/hq-lib-tls-go/client/internal/record"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

// errChangeCipherSpec signals that the peer sent a ChangeCipherSpec.
var errChangeCipherSpec = errors.New("change cipher spec")

// helloRetryRequestRandom is the special ServerHello.random that marks a
// TLS 1.3 HelloRetryRequest.
var helloRetryRequestRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// extensionInfo is one parsed extension.
type extensionInfo struct {
	Type uint16
	Data []byte
}

// keyShareEntry is one key_share entry.
type keyShareEntry struct {
	Group uint16
	Data  []byte
}

// clientHelloState is the client side of the hello exchange.
type clientHelloState struct {
	legacyVersion        uint16
	random               []byte
	sessionID            []byte
	suites               []uint16
	keyShares            map[uint16]*ecdh.PrivateKey
	keyShareEntries      []keyShareEntry
	serverName           string
	alpn                 []string
	supportedGroups      []CurveID
	signatureAlgorithms  []SignatureScheme
	extendedMasterSecret bool
}

// serverHelloInfo is the parsed ServerHello.
type serverHelloInfo struct {
	legacyVersion        uint16
	version              uint16
	random               []byte
	sessionID            []byte
	suiteID              uint16
	suite                hqgotlsciphers.Suite
	compression          uint8
	extensions           []extensionInfo
	keyShare             *keyShareEntry
	cookie               []byte
	alpn                 string
	extendedMasterSecret bool
	sessionTicket        bool
	helloRetryRequest    bool
}

// serverKeyExchangeInfo is the parsed ServerKeyExchange.
type serverKeyExchangeInfo struct {
	params             []byte
	signatureAlgorithm uint16
	signature          []byte
	dhP                *big.Int
	dhG                *big.Int
	dhYs               *big.Int
	rsaPublicKey       *rsa.PublicKey
	curveID            uint16
	ecPoint            []byte
	anon               bool
}

// certificateRequestInfo is the parsed CertificateRequest.
type certificateRequestInfo struct {
	certificateTypes       []uint8
	signatureAlgorithms    []uint16
	certificateAuthorities [][]byte
}

// clientHandshake runs the client handshake.
func (c *Conn) clientHandshake(ctx context.Context) (err error) {
	c.in = &record.State{Conn: c.conn}
	c.out = &record.State{Conn: c.conn}

	stop := context.AfterFunc(ctx, func() {
		_ = c.conn.SetDeadline(time.Now())
	})
	defer stop()

	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(deadline)

		defer func() {
			_ = c.conn.SetDeadline(time.Time{})
		}()
	}

	if err = ctx.Err(); err != nil {
		return hqgoerrors.Wrap(err, "handshake context")
	}

	hello, body, err := c.buildClientHello()
	if err != nil {
		return err
	}

	c.out.Version = hello.legacyVersion

	if err = c.writeHandshakeMessage(HandshakeClientHello, body); err != nil {
		return hqgoerrors.Wrap(err, "writing ClientHello")
	}

	var serverHello *serverHelloInfo

	for {
		typ, body, raw, readErr := c.readHandshakeMessage()
		if errors.Is(readErr, errChangeCipherSpec) {
			// TLS 1.3 compatibility ChangeCipherSpec messages may arrive at
			// any point and are ignored.
			continue
		}

		if readErr != nil {
			return hqgoerrors.Wrap(readErr, "reading ServerHello")
		}

		if typ != HandshakeServerHello {
			return hqgoerrors.Errorf("expected ServerHello, got %s", typ)
		}

		serverHello, readErr = parseServerHello(body)
		if readErr != nil {
			return hqgoerrors.Wrap(readErr, "parsing ServerHello")
		}

		if !serverHello.helloRetryRequest {
			break
		}

		if readErr := c.handleHelloRetryRequest(hello, serverHello, raw); readErr != nil {
			return readErr
		}
	}

	if !c.config.supportsVersion(serverHello.version) {
		return hqgoerrors.Errorf("%w: server selected %#x outside the configured range", ErrUnsupportedVersion, serverHello.version)
	}

	if !serverHello.suite.Implemented {
		return hqgoerrors.Errorf("%w: %s", ErrUnsupportedCipherSuite, serverHello.suite.Name)
	}

	if len(c.config.CipherSuites) > 0 && !hasSuite(c.config.CipherSuites, serverHello.suiteID) {
		return hqgoerrors.Errorf("%w: server selected unoffered suite %s", ErrUnsupportedCipherSuite, serverHello.suite.Name)
	}

	c.withState(func(state *ConnectionState) {
		state.Version = serverHello.version
		state.CipherSuite = serverHello.suiteID
		state.ExportCipher = serverHello.suite.Export
	})

	c.in.Version = serverHello.version
	c.out.Version = serverHello.version

	if serverHello.version == VersionTLS13 {
		return c.clientHandshakeTLS13(ctx, hello, serverHello)
	}

	return c.clientHandshakeTLS12(ctx, hello, serverHello)
}

// handleHelloRetryRequest processes a TLS 1.3 HelloRetryRequest and sends the
// second ClientHello.
func (c *Conn) handleHelloRetryRequest(hello *clientHelloState, serverHello *serverHelloInfo, retryRaw []byte) (err error) {
	if c.config.ClientHelloSpec != nil {
		return hqgoerrors.Errorf("%w: TLS 1.3 HelloRetryRequest is not supported with a custom ClientHelloSpec", ErrUnsupportedVersion)
	}

	if serverHello.keyShare == nil {
		return hqgoerrors.New("invalid input, HelloRetryRequest has no key_share")
	}

	if len(c.transcript) < len(retryRaw) {
		return hqgoerrors.New("invalid input, handshake transcript is shorter than the HelloRetryRequest")
	}

	firstClientHello := c.transcript[:len(c.transcript)-len(retryRaw)]
	hashName := hqgotlsclientkeys.HashNameForSuite(serverHello.suite.Hash)

	c.transcript = append(marshalHandshake(HandshakeMessageHash, hqgotlsclientkeys.TranscriptHash(hashName, firstClientHello)), retryRaw...)

	// RFC 8446 permits a new ClientHello.random here, but some servers
	// (including Go's) require the second ClientHello to match the first in
	// every field except the key_share and cookie. Keep the original random.
	group := serverHello.keyShare.Group

	curve := ecdhCurve(group)
	if curve == nil {
		return hqgoerrors.Errorf("%w: unsupported retry group %#x", ErrUnsupportedCipherSuite, group)
	}

	private, err := curve.GenerateKey(c.config.randReader())
	if err != nil {
		return hqgoerrors.Wrap(err, "generating retry key share")
	}

	hello.keyShares = map[uint16]*ecdh.PrivateKey{group: private}
	hello.keyShareEntries = []keyShareEntry{{Group: group, Data: private.PublicKey().Bytes()}}

	body, err := c.buildRetryClientHello(hello, serverHello.cookie)
	if err != nil {
		return err
	}

	return c.writeHandshakeMessage(HandshakeClientHello, body)
}

// buildRetryClientHello builds the second ClientHello after a
// HelloRetryRequest.
func (c *Conn) buildRetryClientHello(hello *clientHelloState, cookie []byte) (body []byte, err error) {
	extensions := make([]extensionInfo, 0, 12)

	if hello.serverName != "" && net.ParseIP(hello.serverName) == nil {
		extensions = append(extensions, extensionInfo{Type: extensionServerName, Data: marshalSNI(hello.serverName)})
	}

	extensions = append(extensions,
		extensionInfo{Type: extensionSupportedGroups, Data: marshalGroups(hello.supportedGroups)},
		extensionInfo{Type: extensionECPointFormats, Data: []byte{1, 0}},
	)

	if len(hello.signatureAlgorithms) > 0 {
		extensions = append(extensions, extensionInfo{Type: extensionSignatureAlgorithms, Data: marshalSignatureAlgorithms(hello.signatureAlgorithms)})
	}

	if len(hello.alpn) > 0 {
		extensions = append(extensions, extensionInfo{Type: extensionALPN, Data: marshalALPN(hello.alpn)})
	}

	extensions = append(extensions,
		extensionInfo{Type: extensionStatusRequest, Data: []byte{1, 0, 0, 0, 0}},
		extensionInfo{Type: extensionExtendedMasterSecret},
		extensionInfo{Type: extensionSessionTicket},
		extensionInfo{Type: extensionRenegotiationInfo, Data: []byte{0}},
		extensionInfo{Type: extensionSupportedVersions, Data: marshalSupportedVersions(c.config.MaxVersion, c.config.MinVersion)},
		extensionInfo{Type: extensionKeyShare, Data: marshalKeyShares(hello.keyShareEntries)},
	)

	if cookie != nil {
		cookieBody, cookieErr := message.AppendVector16(nil, cookie)
		if cookieErr != nil {
			return nil, cookieErr
		}

		extensions = append(extensions, extensionInfo{Type: extensionCookie, Data: cookieBody})
	}

	extensionsRaw, err := marshalExtensions(extensions)
	if err != nil {
		return nil, err
	}

	body = buildClientHelloBody(hello.legacyVersion, hello.random, hello.sessionID, hello.suites, []uint8{0}, extensionsRaw)

	return body, nil
}

// clientHandshakeTLS12 runs the TLS 1.0-1.2 and SSL 3.0 client handshake.
func (c *Conn) clientHandshakeTLS12(ctx context.Context, hello *clientHelloState, serverHello *serverHelloInfo) (err error) {
	var (
		certificates       [][]byte
		leaf               *x509.Certificate
		keyExchange        *serverKeyExchangeInfo
		certRequest        *certificateRequestInfo
		gotServerHelloDone bool
	)

	for {
		if err = ctx.Err(); err != nil {
			return hqgoerrors.Wrap(err, "handshake context")
		}

		typ, body, _, readErr := c.readHandshakeMessage()
		if readErr != nil {
			return hqgoerrors.Wrap(readErr, "reading server flight")
		}

		switch typ { //nolint:exhaustive // only server-flight messages are valid here.
		case HandshakeCertificate:
			certificates, err = parseCertificateMessage(body, serverHello.version)
			if err != nil {
				return hqgoerrors.Wrap(err, "parsing server Certificate")
			}

			if len(certificates) == 0 {
				return ErrNoCertificates
			}

			leaf, err = x509.ParseCertificate(certificates[0])
			if err != nil {
				return hqgoerrors.Wrap(err, "parsing leaf certificate")
			}

			if err := c.verifyCertificateChain(certificates); err != nil {
				return err
			}
		case HandshakeServerKeyExchange:
			keyExchange, err = parseServerKeyExchange(body, serverHello)
			if err != nil {
				return hqgoerrors.Wrap(err, "parsing ServerKeyExchange")
			}
		case HandshakeCertificateRequest:
			certRequest, err = parseCertificateRequest(body, serverHello.version)
			if err != nil {
				return hqgoerrors.Wrap(err, "parsing CertificateRequest")
			}
		case HandshakeCertificateStatus:
			// OCSP stapling is captured by the trace but not exposed yet.
		case HandshakeServerHelloDone:
			gotServerHelloDone = true
		default:
			return hqgoerrors.Errorf("unexpected handshake message %s in server flight", typ)
		}

		if gotServerHelloDone {
			break
		}
	}

	if serverHello.suite.Authentication != "none" && leaf == nil {
		return ErrNoCertificates
	}

	if keyExchange != nil && !keyExchange.anon {
		if err := verifyServerKeyExchange(leaf, keyExchange, hello.random, serverHello.random, serverHello.version); err != nil {
			return err
		}
	}

	var clientCertificate *Certificate

	if certRequest != nil {
		clientCertificate, err = c.selectClientCertificate(certRequest)
		if err != nil {
			return hqgoerrors.Wrap(err, "GetClientCertificate")
		}

		if err = c.writeHandshakeMessage(HandshakeCertificate, clientCertificateMessage(clientCertificate)); err != nil {
			return hqgoerrors.Wrap(err, "writing client Certificate")
		}
	}

	ckeBody, preMaster, err := c.buildClientKeyExchange(hello, serverHello, leaf, keyExchange)
	if err != nil {
		return hqgoerrors.Wrap(err, "building ClientKeyExchange")
	}

	if err = c.writeHandshakeMessage(HandshakeClientKeyExchange, ckeBody); err != nil {
		return hqgoerrors.Wrap(err, "writing ClientKeyExchange")
	}

	masterSecret := hqgotlsclientkeys.DeriveMasterSecret(
		serverHello.version,
		&serverHello.suite,
		preMaster,
		hello.random,
		serverHello.random,
		c.transcript,
		serverHello.extendedMasterSecret,
	)

	c.logMasterSecret(hello.random, masterSecret)

	keyBlock, err := hqgotlsclientkeys.DeriveKeyBlock(serverHello.version, &serverHello.suite, masterSecret, hello.random, serverHello.random)
	if err != nil {
		return hqgoerrors.Wrap(err, "deriving key block")
	}

	if clientCertificate != nil {
		if err := c.sendCertificateVerify(clientCertificate, certRequest, serverHello.version); err != nil {
			return err
		}
	}

	if err = c.sendChangeCipherSpec(); err != nil {
		return hqgoerrors.Wrap(err, "sending ChangeCipherSpec")
	}

	if err := c.installWriteKeys(&keyBlock, serverHello); err != nil {
		return err
	}

	clientVerify := hqgotlsclientkeys.FinishedVerifyData(serverHello.version, &serverHello.suite, masterSecret, c.transcript, "CLNT")

	if err = c.writeHandshakeMessage(HandshakeFinished, clientVerify); err != nil {
		return hqgoerrors.Wrap(err, "writing client Finished")
	}

	for {
		typ, body, raw, readErr := c.readHandshakeMessage()
		if errors.Is(readErr, errChangeCipherSpec) {
			if err := c.installReadKeys(&keyBlock, serverHello); err != nil {
				return err
			}

			continue
		}

		if readErr != nil {
			return hqgoerrors.Wrap(readErr, "reading server Finished")
		}

		if typ == HandshakeNewSessionTicket {
			continue
		}

		if typ != HandshakeFinished {
			return hqgoerrors.Errorf("expected server Finished, got %s", typ)
		}

		expected := hqgotlsclientkeys.FinishedVerifyData(serverHello.version, &serverHello.suite, masterSecret, c.transcript, "SRVR")
		if subtle.ConstantTimeCompare(body, expected) != 1 {
			return hqgoerrors.Wrap(ErrVerifyFailed, "server Finished verify_data mismatch")
		}

		c.transcript = append(c.transcript, raw...)

		break
	}

	c.withState(func(state *ConnectionState) {
		state.HandshakeComplete = true
		state.NegotiatedProtocol = serverHello.alpn
		state.ServerName = c.config.ServerName
		state.PeerCertificates = peerCertificates(certificates)
	})

	if c.config.VerifyConnection != nil {
		if err = c.config.VerifyConnection(c.ConnectionState()); err != nil {
			return hqgoerrors.Wrap(err, "VerifyConnection")
		}
	}

	return nil
}

// clientHandshakeTLS13 is implemented in handshake_client_tls13.go.
func (c *Conn) clientHandshakeTLS13(ctx context.Context, hello *clientHelloState, serverHello *serverHelloInfo) (err error) {
	return c.tls13Handshake(ctx, hello, serverHello)
}

// buildClientHello builds the ClientHello body and its local state.
func (c *Conn) buildClientHello() (hello *clientHelloState, body []byte, err error) {
	config := c.config

	hello = &clientHelloState{
		legacyVersion:       config.MaxVersion,
		serverName:          config.ServerName,
		alpn:                append([]string(nil), config.NextProtos...),
		supportedGroups:     c.supportedGroups(),
		signatureAlgorithms: c.signatureAlgorithms(),
	}

	if hello.legacyVersion > VersionTLS12 {
		hello.legacyVersion = VersionTLS12
	}

	hello.random = make([]byte, 32)
	if _, err = io.ReadFull(config.randReader(), hello.random); err != nil {
		return nil, nil, hqgoerrors.Wrap(err, "generating ClientHello random")
	}

	hello.sessionID = make([]byte, 32)
	if _, err = io.ReadFull(config.randReader(), hello.sessionID); err != nil {
		return nil, nil, hqgoerrors.Wrap(err, "generating session ID")
	}

	for _, id := range config.CipherSuites {
		suite, known := hqgotlsciphers.ByID(id)
		if !known {
			hello.suites = append(hello.suites, id)

			continue
		}

		for _, version := range suite.Versions {
			if version >= config.MinVersion && version <= config.MaxVersion {
				hello.suites = append(hello.suites, id)

				break
			}
		}
	}

	if len(hello.suites) == 0 {
		return nil, nil, hqgoerrors.New("no cipher suites intersect the configured version range")
	}

	if config.ClientHelloSpec != nil {
		return c.buildClientHelloFromSpec(hello)
	}

	extensions := c.defaultExtensions(hello)

	if config.MaxVersion <= VersionSSL30 {
		extensions = nil
	}

	extensionsRaw, err := marshalExtensions(extensions)
	if err != nil {
		return nil, nil, err
	}

	body = buildClientHelloBody(hello.legacyVersion, hello.random, hello.sessionID, hello.suites, []uint8{0}, extensionsRaw)

	return hello, body, nil
}

// buildClientHelloFromSpec builds a ClientHello from an explicit spec.
func (c *Conn) buildClientHelloFromSpec(hello *clientHelloState) (built *clientHelloState, body []byte, err error) {
	spec := c.config.ClientHelloSpec

	hello.legacyVersion = spec.TLSVersMax
	if hello.legacyVersion > VersionTLS12 {
		hello.legacyVersion = VersionTLS12
	}

	if len(spec.CipherSuites) > 0 {
		hello.suites = append([]uint16(nil), spec.CipherSuites...)
	}

	compression := spec.CompressionMethods
	if len(compression) == 0 {
		compression = []uint8{0}
	}

	keyShareAdded := false

	if spec.TLSVersMax >= VersionTLS13 {
		groups := hello.supportedGroups

		for _, extension := range spec.Extensions {
			switch typed := extension.(type) {
			case SupportedGroupsExtension:
				groups = typed.Groups
			case *SupportedGroupsExtension:
				groups = typed.Groups
			}
		}

		shares, entries, keyShareErr := c.generateKeyShares(groups)
		if keyShareErr != nil {
			return nil, nil, keyShareErr
		}

		hello.keyShares = shares
		hello.keyShareEntries = entries
	}

	extensions := make([]extensionInfo, 0, len(spec.Extensions)+1)

	for _, extension := range spec.Extensions {
		if extension == nil {
			continue
		}

		if extension.ExtensionType() == extensionKeyShare {
			if keyShareAdded {
				continue
			}

			extensions = append(extensions, extensionInfo{
				Type: extensionKeyShare,
				Data: marshalKeyShares(hello.keyShareEntries),
			})

			keyShareAdded = true

			continue
		}

		extensionBody, marshalErr := extension.Marshal()
		if marshalErr != nil {
			return nil, nil, hqgoerrors.Wrapf(marshalErr, "marshaling extension %#x", extension.ExtensionType())
		}

		extensions = append(extensions, extensionInfo{
			Type: extension.ExtensionType(),
			Data: extensionBody,
		})
	}

	if spec.TLSVersMax >= VersionTLS13 && !keyShareAdded {
		extensions = append(extensions, extensionInfo{
			Type: extensionKeyShare,
			Data: marshalKeyShares(hello.keyShareEntries),
		})
	}

	if spec.GREASE {
		hello.suites = append([]uint16{c.randomGrease()}, hello.suites...)
		extensions = append([]extensionInfo{{Type: c.randomGrease()}}, extensions...)
	}

	extensionsRaw, err := marshalExtensions(extensions)
	if err != nil {
		return nil, nil, err
	}

	body = buildClientHelloBody(hello.legacyVersion, hello.random, hello.sessionID, hello.suites, compression, extensionsRaw)

	return hello, body, nil
}

// defaultExtensions builds the client's default extension block.
func (c *Conn) defaultExtensions(hello *clientHelloState) (extensions []extensionInfo) {
	config := c.config

	if hello.serverName != "" && net.ParseIP(hello.serverName) == nil {
		extensions = append(extensions, extensionInfo{Type: extensionServerName, Data: marshalSNI(hello.serverName)})
	}

	if len(hello.supportedGroups) > 0 {
		extensions = append(extensions,
			extensionInfo{Type: extensionSupportedGroups, Data: marshalGroups(hello.supportedGroups)},
			extensionInfo{Type: extensionECPointFormats, Data: []byte{1, 0}},
		)
	}

	if len(hello.signatureAlgorithms) > 0 {
		extensions = append(extensions, extensionInfo{Type: extensionSignatureAlgorithms, Data: marshalSignatureAlgorithms(hello.signatureAlgorithms)})
	}

	if len(hello.alpn) > 0 {
		extensions = append(extensions, extensionInfo{Type: extensionALPN, Data: marshalALPN(hello.alpn)})
	}

	extensions = append(extensions, extensionInfo{Type: extensionStatusRequest, Data: []byte{1, 0, 0, 0, 0}})

	if config.MinVersion >= VersionTLS10 {
		extensions = append(extensions, extensionInfo{Type: extensionExtendedMasterSecret})
		hello.extendedMasterSecret = true
	}

	extensions = append(extensions,
		extensionInfo{Type: extensionSessionTicket},
		extensionInfo{Type: extensionRenegotiationInfo, Data: []byte{0}},
	)

	if config.MaxVersion >= VersionTLS13 {
		extensions = append(extensions, extensionInfo{Type: extensionSupportedVersions, Data: marshalSupportedVersions(config.MaxVersion, config.MinVersion)})

		shares, shareEntries, keyShareErr := c.generateKeyShares(c.keyShareGroups(hello))
		if keyShareErr != nil {
			return extensions
		}

		hello.keyShares = shares
		hello.keyShareEntries = shareEntries

		extensions = append(extensions, extensionInfo{Type: extensionKeyShare, Data: marshalKeyShares(shareEntries)})
	}

	return extensions
}

// randomGrease returns a random GREASE value.
func (c *Conn) randomGrease() (value uint16) {
	var raw [1]byte

	if _, err := io.ReadFull(c.config.randReader(), raw[:]); err != nil {
		return greaseValues[0]
	}

	return greaseValues[int(raw[0])%len(greaseValues)]
}

// buildClientHelloBody serializes a ClientHello body.
func buildClientHelloBody(legacyVersion uint16, randomBytes, sessionID []byte, suites []uint16, compression []uint8, extensions []byte) (body []byte) {
	body = message.AppendUint16(nil, legacyVersion)
	body = append(body, randomBytes...)
	body, _ = message.AppendVector8(body, sessionID)

	suitesRaw := make([]byte, 0, len(suites)*2)
	for _, suite := range suites {
		suitesRaw = message.AppendUint16(suitesRaw, suite)
	}

	body, _ = message.AppendVector16(body, suitesRaw)
	body, _ = message.AppendVector8(body, compression)

	if extensions != nil {
		body = append(body, extensions...)
	}

	return body
}

// parseServerHello parses a ServerHello body.
func parseServerHello(body []byte) (serverHello *serverHelloInfo, err error) {
	serverHello = &serverHelloInfo{}

	r := message.NewReader(body)

	serverHello.legacyVersion = r.Uint16()
	serverHello.version = serverHello.legacyVersion

	serverHello.random = append([]byte(nil), r.Bytes(32)...)
	serverHello.sessionID = append([]byte(nil), r.Vector8()...)
	serverHello.suiteID = r.Uint16()
	serverHello.compression = r.Uint8()

	if r.Remaining() > 0 {
		extensionsRaw := r.Vector16()

		serverHello.extensions, err = parseExtensions(extensionsRaw)
		if err != nil {
			return nil, err
		}
	}

	if err := r.Error(); err != nil {
		return nil, err
	}

	if bytes.Equal(serverHello.random, helloRetryRequestRandom) {
		serverHello.helloRetryRequest = true
	}

	for _, extension := range serverHello.extensions {
		switch extension.Type {
		case extensionSupportedVersions:
			ext := message.NewReader(extension.Data)
			serverHello.version = ext.Uint16()
		case extensionKeyShare:
			ext := message.NewReader(extension.Data)
			group := ext.Uint16()

			var data []byte
			if ext.Remaining() >= 2 {
				data = append([]byte(nil), ext.Vector16()...)
			}

			serverHello.keyShare = &keyShareEntry{Group: group, Data: data}
		case extensionCookie:
			ext := message.NewReader(extension.Data)
			serverHello.cookie = append([]byte(nil), ext.Vector16()...)
		case extensionALPN:
			ext := message.NewReader(extension.Data)
			list := ext.Vector16()
			protocols := message.NewReader(list)

			for protocols.Remaining() > 0 {
				protocol := string(protocols.Vector8())
				if serverHello.alpn == "" {
					serverHello.alpn = protocol
				}
			}
		case extensionExtendedMasterSecret:
			serverHello.extendedMasterSecret = true
		case extensionSessionTicket:
			serverHello.sessionTicket = true
		}
	}

	suite, known := hqgotlsciphers.ByID(serverHello.suiteID)
	if !known {
		return nil, hqgoerrors.Errorf("%w: %#x", ErrUnsupportedCipherSuite, serverHello.suiteID)
	}

	serverHello.suite = suite

	return serverHello, nil
}

// parseExtensions parses an extension block.
func parseExtensions(raw []byte) (extensions []extensionInfo, err error) {
	r := message.NewReader(raw)

	for r.Remaining() > 0 {
		typ := r.Uint16()
		data := append([]byte(nil), r.Vector16()...)

		extensions = append(extensions, extensionInfo{Type: typ, Data: data})
	}

	if err := r.Error(); err != nil {
		return nil, err
	}

	return extensions, nil
}

// parseCertificateMessage parses a Certificate message.
func parseCertificateMessage(body []byte, version uint16) (certificates [][]byte, err error) {
	if version >= VersionTLS13 {
		r := message.NewReader(body)
		_ = r.Vector8() // certificate_request_context
		list := r.Vector24()

		entries := message.NewReader(list)

		for entries.Remaining() > 0 {
			cert := append([]byte(nil), entries.Vector24()...)
			_ = entries.Vector16() // per-certificate extensions

			certificates = append(certificates, cert)
		}

		if err := entries.Error(); err != nil {
			return nil, err
		}

		return certificates, nil
	}

	r := message.NewReader(body)
	list := r.Vector24()

	entries := message.NewReader(list)

	for entries.Remaining() > 0 {
		certificates = append(certificates, append([]byte(nil), entries.Vector24()...))
	}

	if err := entries.Error(); err != nil {
		return nil, err
	}

	return certificates, nil
}

// parseServerKeyExchange parses a ServerKeyExchange message.
func parseServerKeyExchange(body []byte, serverHello *serverHelloInfo) (info *serverKeyExchangeInfo, err error) {
	info = &serverKeyExchangeInfo{}

	r := message.NewReader(body)
	paramsStart := r.Offset()

	switch serverHello.suite.KeyExchange { //nolint:exhaustive // unsupported key exchanges fall through to the default error.
	case hqgotlsciphers.KeyExchangeRSAExport:
		modulus := r.Vector16()
		exponent := r.Vector16()

		info.rsaPublicKey = &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(new(big.Int).SetBytes(exponent).Int64()),
		}

		info.params = append([]byte(nil), body[paramsStart:r.Offset()]...)
	case hqgotlsciphers.KeyExchangeDHE, hqgotlsciphers.KeyExchangeDHEExport:
		p := r.Vector16()
		g := r.Vector16()
		ys := r.Vector16()

		info.dhP = new(big.Int).SetBytes(p)
		info.dhG = new(big.Int).SetBytes(g)
		info.dhYs = new(big.Int).SetBytes(ys)

		info.params = append([]byte(nil), body[paramsStart:r.Offset()]...)
	case hqgotlsciphers.KeyExchangeDHAnon, hqgotlsciphers.KeyExchangeDHAnonExp:
		p := r.Vector16()
		g := r.Vector16()
		ys := r.Vector16()

		info.dhP = new(big.Int).SetBytes(p)
		info.dhG = new(big.Int).SetBytes(g)
		info.dhYs = new(big.Int).SetBytes(ys)

		info.params = append([]byte(nil), body[paramsStart:r.Offset()]...)
		info.anon = true
	case hqgotlsciphers.KeyExchangeECDHE:
		curveType := r.Uint8()
		if curveType != 3 {
			return nil, hqgoerrors.Errorf("unsupported ECPoint curve type %d", curveType)
		}

		info.curveID = r.Uint16()
		info.ecPoint = append([]byte(nil), r.Vector8()...)
		info.params = append([]byte(nil), body[paramsStart:r.Offset()]...)
	default:
		return nil, hqgoerrors.Errorf("%w: key exchange %s", ErrUnsupportedCipherSuite, serverHello.suite.KeyExchange)
	}

	if info.anon {
		return info, nil
	}

	if serverHello.version >= VersionTLS12 {
		info.signatureAlgorithm = r.Uint16()
	}

	info.signature = append([]byte(nil), r.Vector16()...)

	if err := r.Error(); err != nil {
		return nil, err
	}

	return info, nil
}

// parseCertificateRequest parses a CertificateRequest message.
func parseCertificateRequest(body []byte, version uint16) (request *certificateRequestInfo, err error) {
	request = &certificateRequestInfo{}

	r := message.NewReader(body)
	request.certificateTypes = append([]uint8(nil), r.Vector8()...)

	if version >= VersionTLS12 {
		raw := r.Vector16()
		algorithms := message.NewReader(raw)

		for algorithms.Remaining() >= 2 {
			request.signatureAlgorithms = append(request.signatureAlgorithms, algorithms.Uint16())
		}
	}

	authorities := r.Vector16()
	authorityReader := message.NewReader(authorities)

	for authorityReader.Remaining() > 0 {
		request.certificateAuthorities = append(request.certificateAuthorities, append([]byte(nil), authorityReader.Vector16()...))
	}

	if err := r.Error(); err != nil {
		return nil, err
	}

	return request, nil
}

// buildClientKeyExchange builds the ClientKeyExchange body and premaster
// secret.
func (c *Conn) buildClientKeyExchange(hello *clientHelloState, serverHello *serverHelloInfo, leaf *x509.Certificate, keyExchange *serverKeyExchangeInfo) (body, preMaster []byte, err error) {
	switch serverHello.suite.KeyExchange { //nolint:exhaustive // unsupported key exchanges fall through to the default error.
	case hqgotlsciphers.KeyExchangeRSA, hqgotlsciphers.KeyExchangeRSAExport:
		var publicKey *rsa.PublicKey

		if serverHello.suite.KeyExchange == hqgotlsciphers.KeyExchangeRSAExport {
			if keyExchange == nil || keyExchange.rsaPublicKey == nil {
				return nil, nil, hqgoerrors.New("invalid input, RSA_EXPORT requires a temporary key")
			}

			publicKey = keyExchange.rsaPublicKey
		} else {
			var ok bool

			publicKey, ok = leaf.PublicKey.(*rsa.PublicKey)
			if !ok {
				return nil, nil, hqgoerrors.Errorf("%w: server certificate is not RSA", ErrUnsupportedCipherSuite)
			}
		}

		preMaster = make([]byte, 48)
		preMaster[0] = byte(hello.legacyVersion >> 8)
		preMaster[1] = byte(hello.legacyVersion) //nolint:gosec // G115: legacyVersion is a two-byte protocol version.

		if _, err = io.ReadFull(rand.Reader, preMaster[2:]); err != nil {
			return nil, nil, hqgoerrors.Wrap(err, "generating premaster secret")
		}

		encrypted, encryptErr := rsa.EncryptPKCS1v15(c.config.randReader(), publicKey, preMaster) //nolint:staticcheck // SA1019: RSA key exchange is required for legacy TLS.
		if encryptErr != nil {
			return nil, nil, hqgoerrors.Wrap(encryptErr, "encrypting premaster secret")
		}

		if serverHello.version == VersionSSL30 {
			body = encrypted
		} else {
			body, _ = message.AppendVector16(nil, encrypted)
		}
	case hqgotlsciphers.KeyExchangeDHE, hqgotlsciphers.KeyExchangeDHEExport, hqgotlsciphers.KeyExchangeDHAnon, hqgotlsciphers.KeyExchangeDHAnonExp:
		if keyExchange == nil || keyExchange.dhP == nil {
			return nil, nil, hqgoerrors.New("invalid input, DHE requires server parameters")
		}

		if c.config.MinDHBits > 0 && keyExchange.dhP.BitLen() < c.config.MinDHBits {
			return nil, nil, hqgoerrors.Errorf("%w: DH group is %d bits, minimum is %d", ErrVerifyFailed, keyExchange.dhP.BitLen(), c.config.MinDHBits)
		}

		private, public, privateErr := dhKeyPair(c.config.randReader(), keyExchange.dhP, keyExchange.dhG)
		if privateErr != nil {
			return nil, nil, privateErr
		}

		shared := new(big.Int).Exp(keyExchange.dhYs, private, keyExchange.dhP)
		preMaster = leftPad(shared.Bytes(), (keyExchange.dhP.BitLen()+7)/8)

		body, _ = message.AppendVector16(nil, public.Bytes())
	case hqgotlsciphers.KeyExchangeECDHE:
		curve := ecdhCurve(keyExchange.curveID)
		if curve == nil {
			return nil, nil, hqgoerrors.Errorf("%w: unsupported curve %#x", ErrUnsupportedCipherSuite, keyExchange.curveID)
		}

		private, keyErr := curve.GenerateKey(c.config.randReader())
		if keyErr != nil {
			return nil, nil, hqgoerrors.Wrap(keyErr, "generating ECDHE key")
		}

		peer, keyErr := curve.NewPublicKey(keyExchange.ecPoint)
		if keyErr != nil {
			return nil, nil, hqgoerrors.Wrap(keyErr, "parsing server ECDHE key")
		}

		preMaster, keyErr = private.ECDH(peer)
		if keyErr != nil {
			return nil, nil, hqgoerrors.Wrap(keyErr, "computing ECDHE shared secret")
		}

		body, _ = message.AppendVector8(nil, private.PublicKey().Bytes())
	default:
		return nil, nil, hqgoerrors.Errorf("%w: key exchange %s", ErrUnsupportedCipherSuite, serverHello.suite.KeyExchange)
	}

	return body, preMaster, nil
}

// selectClientCertificate chooses the client certificate for a request.
func (c *Conn) selectClientCertificate(request *certificateRequestInfo) (certificate *Certificate, err error) {
	if c.config.GetClientCertificate != nil {
		return c.config.GetClientCertificate(&CertificateRequestInfo{
			SignatureSchemes: schemesFromIDs(request.signatureAlgorithms),
			Version:          c.state.Version,
		})
	}

	if len(c.config.Certificates) > 0 {
		return &c.config.Certificates[0], nil
	}

	return nil, nil //nolint:nilnil // no client certificate is a valid outcome.
}

// clientCertificateMessage builds a TLS 1.2 Certificate message body.
func clientCertificateMessage(certificate *Certificate) (body []byte) {
	if certificate == nil || len(certificate.Certificate) == 0 {
		return []byte{0, 0, 0}
	}

	var list []byte

	for _, der := range certificate.Certificate {
		list, _ = message.AppendVector24(list, der)
	}

	body, _ = message.AppendVector24(nil, list)

	return body
}

// sendCertificateVerify sends a TLS 1.0-1.2 CertificateVerify message.
func (c *Conn) sendCertificateVerify(certificate *Certificate, request *certificateRequestInfo, version uint16) (err error) {
	signature, algorithm, err := signCertificateVerify(certificate, c.transcript, version, request)
	if err != nil {
		return err
	}

	var body []byte

	if version >= VersionTLS12 {
		body = message.AppendUint16(body, algorithm)
	}

	body, _ = message.AppendVector16(body, signature)

	if err = c.writeHandshakeMessage(HandshakeCertificateVerify, body); err != nil {
		return hqgoerrors.Wrap(err, "writing CertificateVerify")
	}

	return nil
}

// verifyCertificateChain verifies the server certificate chain and stores the
// result.
func (c *Conn) verifyCertificateChain(rawCerts [][]byte) (err error) {
	peerCertificates, parseErr := parsePeerCertificates(rawCerts)
	if parseErr != nil {
		return parseErr
	}

	c.withState(func(state *ConnectionState) {
		state.PeerCertificates = peerCertificates
	})

	if c.config.InsecureSkipVerify {
		if c.config.VerifyPeerCertificate != nil {
			if err = c.config.VerifyPeerCertificate(rawCerts, nil); err != nil {
				return hqgoerrors.Wrap(err, "VerifyPeerCertificate")
			}
		}

		return nil
	}

	intermediates := x509.NewCertPool()

	for _, certificate := range peerCertificates[1:] {
		intermediates.AddCert(certificate)
	}

	options := x509.VerifyOptions{
		Roots:         c.config.RootCAs,
		Intermediates: intermediates,
		CurrentTime:   c.config.now(),
	}

	if c.config.ServerName != "" {
		options.DNSName = c.config.ServerName
	}

	chains, verifyErr := peerCertificates[0].Verify(options)
	if verifyErr != nil {
		return hqgoerrors.Join(ErrVerifyFailed, verifyErr)
	}

	c.withState(func(state *ConnectionState) {
		state.VerifiedChains = chains
	})

	if c.config.VerifyPeerCertificate != nil {
		if err = c.config.VerifyPeerCertificate(rawCerts, chains); err != nil {
			return hqgoerrors.Wrap(err, "VerifyPeerCertificate")
		}
	}

	return nil
}

// verifyServerKeyExchange verifies the ServerKeyExchange signature.
func verifyServerKeyExchange(leaf *x509.Certificate, info *serverKeyExchangeInfo, clientRandom, serverRandom []byte, version uint16) (err error) {
	if leaf == nil {
		return hqgoerrors.Wrap(ErrVerifyFailed, "no certificate for ServerKeyExchange")
	}

	signed := make([]byte, 0, len(clientRandom)+len(serverRandom)+len(info.params))
	signed = append(signed, clientRandom...)
	signed = append(signed, serverRandom...)
	signed = append(signed, info.params...)

	algorithm := info.signatureAlgorithm
	if version < VersionTLS12 {
		algorithm = 0
	}

	return verifySignature(leaf, algorithm, signed, info.signature, version)
}

// installWriteKeys installs the client write keys.
func (c *Conn) installWriteKeys(block *hqgotlsclientkeys.KeyBlock, serverHello *serverHelloInfo) (err error) {
	protection, err := record.NewProtection(&serverHello.suite, serverHello.version, block.ClientMAC, block.ClientKey, block.ClientIV, false)
	if err != nil {
		return hqgoerrors.Wrap(err, "building write protection")
	}

	c.out.Protection = protection

	return nil
}

// installReadKeys installs the server read keys.
func (c *Conn) installReadKeys(block *hqgotlsclientkeys.KeyBlock, serverHello *serverHelloInfo) (err error) {
	protection, err := record.NewProtection(&serverHello.suite, serverHello.version, block.ServerMAC, block.ServerKey, block.ServerIV, false)
	if err != nil {
		return hqgoerrors.Wrap(err, "building read protection")
	}

	c.in.Protection = protection

	return nil
}

// writeHandshakeMessage writes one handshake message and records it.
func (c *Conn) writeHandshakeMessage(typ HandshakeType, body []byte) (err error) {
	raw := marshalHandshake(typ, body)

	c.emitEvent(Sent, record.TypeHandshake, typ, c.state.Version, body, raw, c.out.Protection != nil)
	c.transcript = append(c.transcript, raw...)

	for len(raw) > 0 {
		chunk := raw

		if c.config.RecordFragmentation > 0 && len(chunk) > c.config.RecordFragmentation {
			chunk = chunk[:c.config.RecordFragmentation]
		} else if len(chunk) > record.MaxPayload {
			chunk = chunk[:record.MaxPayload]
		}

		if err := c.out.WriteRecord(record.TypeHandshake, chunk); err != nil {
			return err
		}

		raw = raw[len(chunk):]
	}

	return nil
}

// readHandshakeMessage reads one handshake message. Finished is not added to
// the transcript automatically so the caller can verify it first.
func (c *Conn) readHandshakeMessage() (typ HandshakeType, body, raw []byte, err error) {
	for {
		if len(c.handshakeBuf) >= 4 {
			length := int(c.handshakeBuf[1])<<16 | int(c.handshakeBuf[2])<<8 | int(c.handshakeBuf[3])
			if len(c.handshakeBuf) >= 4+length {
				raw = append([]byte(nil), c.handshakeBuf[:4+length]...)
				body = raw[4:]
				typ = HandshakeType(raw[0])
				c.handshakeBuf = c.handshakeBuf[4+length:]

				c.emitEvent(Received, record.TypeHandshake, typ, c.state.Version, body, raw, c.in.Protection != nil)

				if typ != HandshakeFinished && typ != HandshakeCertificateVerify {
					c.transcript = append(c.transcript, raw...)
				}

				return typ, body, raw, nil
			}
		}

		recordType, payload, readErr := c.in.ReadRecord()
		if readErr != nil {
			return 0, nil, nil, readErr
		}

		switch recordType {
		case record.TypeHandshake:
			c.handshakeBuf = append(c.handshakeBuf, payload...)
		case record.TypeChangeCipherSpec:
			c.emitEvent(Received, record.TypeChangeCipherSpec, 0, c.state.Version, payload, payload, c.in.Protection != nil)

			return 0, nil, nil, errChangeCipherSpec
		case record.TypeAlert:
			c.emitEvent(Received, record.TypeAlert, 0, c.state.Version, payload, payload, c.in.Protection != nil)

			return 0, nil, nil, alertFromPayload(payload)
		case record.TypeApplicationData:
			return 0, nil, nil, hqgoerrors.New("unexpected application data during handshake")
		default:
			return 0, nil, nil, hqgoerrors.Errorf("unexpected record type %d during handshake", recordType)
		}
	}
}

// sendChangeCipherSpec sends a ChangeCipherSpec record.
func (c *Conn) sendChangeCipherSpec() (err error) {
	payload := []byte{1}

	c.emitEvent(Sent, record.TypeChangeCipherSpec, 0, c.state.Version, payload, payload, c.out.Protection != nil)

	return c.out.WriteRecord(record.TypeChangeCipherSpec, payload)
}

// emitEvent records a handshake trace event.
func (c *Conn) emitEvent(direction Direction, recordType uint8, typ HandshakeType, version uint16, body, raw []byte, encrypted bool) {
	if c.trace == nil {
		return
	}

	name := ""

	switch recordType {
	case record.TypeHandshake:
		name = typ.String()
	case record.TypeChangeCipherSpec:
		name = "ChangeCipherSpec"
	case record.TypeAlert:
		name = "Alert"
	}

	event := HandshakeEvent{
		Direction:  direction,
		Time:       time.Now(),
		RecordType: recordType,
		Type:       typ,
		Name:       name,
		Version:    version,
		Body:       append([]byte(nil), body...),
		Raw:        append([]byte(nil), raw...),
		Encrypted:  encrypted,
	}

	c.trace.emit(&event)
}

// keyShareGroups returns the groups to send key shares for.
func (c *Conn) keyShareGroups(hello *clientHelloState) (groups []CurveID) {
	if len(c.config.KeyShareGroups) > 0 {
		return append([]CurveID(nil), c.config.KeyShareGroups...)
	}

	return hello.supportedGroups
}

// supportedGroups returns the configured groups or the default set.
func (c *Conn) supportedGroups() (groups []CurveID) {
	if len(c.config.CurvePreferences) > 0 {
		return append([]CurveID(nil), c.config.CurvePreferences...)
	}

	return []CurveID{stdtls.X25519, stdtls.CurveP256, stdtls.CurveP384}
}

// signatureAlgorithms returns the configured schemes or a broad default.
func (c *Conn) signatureAlgorithms() (algorithms []SignatureScheme) {
	if len(c.config.SignatureAlgorithms) > 0 {
		return append([]SignatureScheme(nil), c.config.SignatureAlgorithms...)
	}

	return []SignatureScheme{
		stdtls.PSSWithSHA256,
		stdtls.PSSWithSHA384,
		stdtls.PSSWithSHA512,
		stdtls.ECDSAWithP256AndSHA256,
		stdtls.ECDSAWithP384AndSHA384,
		stdtls.ECDSAWithP521AndSHA512,
		stdtls.PKCS1WithSHA256,
		stdtls.PKCS1WithSHA384,
		stdtls.PKCS1WithSHA512,
		stdtls.PKCS1WithSHA1,
		stdtls.Ed25519,
	}
}

// generateKeyShares generates ephemeral ECDHE keys for the configured groups.
func (c *Conn) generateKeyShares(groups []CurveID) (shares map[uint16]*ecdh.PrivateKey, entries []keyShareEntry, err error) {
	shares = make(map[uint16]*ecdh.PrivateKey, len(groups))

	for _, group := range groups {
		curve := ecdhCurve(uint16(group))
		if curve == nil {
			continue
		}

		private, keyErr := curve.GenerateKey(c.config.randReader())
		if keyErr != nil {
			return nil, nil, hqgoerrors.Wrapf(keyErr, "generating key share for group %#x", uint16(group))
		}

		shares[uint16(group)] = private
		entries = append(entries, keyShareEntry{Group: uint16(group), Data: private.PublicKey().Bytes()})
	}

	return shares, entries, nil
}

// ecdhCurve maps a TLS named group to a crypto/ecdh curve.
func ecdhCurve(group uint16) (curve ecdh.Curve) {
	switch CurveID(group) { //nolint:exhaustive // only the classic curves are implemented.
	case stdtls.X25519:
		curve = ecdh.X25519()
	case stdtls.CurveP256:
		curve = ecdh.P256()
	case stdtls.CurveP384:
		curve = ecdh.P384()
	case stdtls.CurveP521:
		curve = ecdh.P521()
	default:
		curve = nil
	}

	return curve
}

// dhKeyPair generates a DHE key pair for the given group.
func dhKeyPair(reader io.Reader, p, g *big.Int) (private, public *big.Int, err error) {
	if p == nil || g == nil || p.BitLen() == 0 {
		return nil, nil, hqgoerrors.New("invalid input, DH group is empty")
	}

	limit := new(big.Int).Sub(p, big.NewInt(2))

	private, err = rand.Int(reader, limit)
	if err != nil {
		return nil, nil, hqgoerrors.Wrap(err, "generating DH private key")
	}

	private.Add(private, big.NewInt(1))
	public = new(big.Int).Exp(g, private, p)

	return private, public, nil
}

// leftPad pads raw on the left with zeros to length.
func leftPad(raw []byte, length int) (padded []byte) {
	if len(raw) >= length {
		return raw
	}

	padded = make([]byte, length-len(raw)+len(raw))
	copy(padded[length-len(raw):], raw)

	return padded
}

// peerCertificates parses raw certificates for ConnectionState.
func peerCertificates(rawCerts [][]byte) (certificates []*x509.Certificate) {
	certificates, _ = parsePeerCertificates(rawCerts)

	return certificates
}

// parsePeerCertificates parses every certificate in a chain.
func parsePeerCertificates(rawCerts [][]byte) (certificates []*x509.Certificate, err error) {
	for _, raw := range rawCerts {
		certificate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return nil, hqgoerrors.Wrap(parseErr, "parsing peer certificate")
		}

		certificates = append(certificates, certificate)
	}

	return certificates, nil
}

// schemesFromIDs converts raw signature scheme IDs to typed values.
func schemesFromIDs(ids []uint16) (schemes []SignatureScheme) {
	for _, id := range ids {
		schemes = append(schemes, SignatureScheme(id))
	}

	return schemes
}
