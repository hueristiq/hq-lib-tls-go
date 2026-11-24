package client

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"

	hqgotlsclientkeys "github.com/hueristiq/hq-lib-tls-go/client/internal/keys"
	"github.com/hueristiq/hq-lib-tls-go/client/internal/message"
	"github.com/hueristiq/hq-lib-tls-go/client/internal/record"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// tls13ServerCertificateVerifyContext is the CertificateVerify context string.
const tls13ServerCertificateVerifyContext = "TLS 1.3, server CertificateVerify"

// tls13Handshake runs the TLS 1.3 client handshake.
func (c *Conn) tls13Handshake(ctx context.Context, hello *clientHelloState, serverHello *serverHelloInfo) (err error) {
	if serverHello.keyShare == nil {
		return hqgoerrors.New("invalid input, TLS 1.3 ServerHello has no key_share")
	}

	private, ok := hello.keyShares[serverHello.keyShare.Group]
	if !ok {
		return hqgoerrors.Errorf("%w: server selected unoffered key share group %#x", ErrInvalidClientHelloSpec, serverHello.keyShare.Group)
	}

	curve := ecdhCurve(serverHello.keyShare.Group)
	if curve == nil {
		return hqgoerrors.Errorf("%w: unsupported group %#x", ErrUnsupportedCipherSuite, serverHello.keyShare.Group)
	}

	peer, err := curve.NewPublicKey(serverHello.keyShare.Data)
	if err != nil {
		return hqgoerrors.Wrap(err, "parsing server key share")
	}

	sharedSecret, err := private.ECDH(peer)
	if err != nil {
		return hqgoerrors.Wrap(err, "computing TLS 1.3 shared secret")
	}

	hashName := hqgotlsclientkeys.HashNameForSuite(serverHello.suite.Hash)

	schedule := hqgotlsclientkeys.NewSchedule(hashName, sharedSecret, c.transcript)

	serverKey, serverIV, err := schedule.TrafficKey(schedule.ServerHandshakeSecret, &serverHello.suite)
	if err != nil {
		return err
	}

	serverProtection, err := record.NewProtection(&serverHello.suite, VersionTLS13, nil, serverKey, serverIV, true)
	if err != nil {
		return err
	}

	c.in.Protection = serverProtection
	c.in.TLS13 = true
	c.in.Version = VersionTLS12
	c.out.TLS13 = true
	c.out.Version = VersionTLS12

	c.withState(func(state *ConnectionState) {
		state.Version = VersionTLS13
		state.CipherSuite = serverHello.suiteID
		state.ExportCipher = false
	})

	var (
		certificates      [][]byte
		leaf              *x509.Certificate
		certRequest       *tls13CertificateRequest
		certVerify        *tls13CertificateVerify
		serverFinished    []byte
		serverFinishedRaw []byte
		negotiatedALPN    string
	)

	for {
		if err = ctx.Err(); err != nil {
			return hqgoerrors.Wrap(err, "handshake context")
		}

		typ, body, raw, readErr := c.readHandshakeMessage()
		if errors.Is(readErr, errChangeCipherSpec) {
			// TLS 1.3 compatibility ChangeCipherSpec messages are ignored.
			continue
		}

		if readErr != nil {
			return hqgoerrors.Wrap(readErr, "reading TLS 1.3 server flight")
		}

		switch typ { //nolint:exhaustive // only the TLS 1.3 server-flight messages are valid here.
		case HandshakeEncryptedExtensions:
			negotiatedALPN, err = parseTLS13EncryptedExtensions(body)
			if err != nil {
				return err
			}
		case HandshakeCertificateRequest:
			certRequest, err = parseTLS13CertificateRequest(body)
			if err != nil {
				return err
			}
		case HandshakeCertificate:
			certificates, err = parseCertificateMessage(body, VersionTLS13)
			if err != nil {
				return hqgoerrors.Wrap(err, "parsing TLS 1.3 Certificate")
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
		case HandshakeCertificateVerify:
			certVerify, err = parseTLS13CertificateVerify(body)
			if err != nil {
				return err
			}

			if leaf == nil {
				return ErrNoCertificates
			}

			signed := tls13CertificateVerifyInput(tls13ServerCertificateVerifyContext, hashName, c.transcript)

			if err := verifySignature(leaf, certVerify.algorithm, signed, certVerify.signature, VersionTLS13); err != nil {
				return err
			}

			c.transcript = append(c.transcript, raw...)
		case HandshakeFinished:
			serverFinished = append([]byte(nil), body...)
			serverFinishedRaw = append([]byte(nil), raw...)
		default:
			return hqgoerrors.Errorf("unexpected TLS 1.3 handshake message %s", typ)
		}

		if serverFinished != nil {
			break
		}
	}

	if certVerify == nil {
		return hqgoerrors.Wrap(ErrVerifyFailed, "TLS 1.3 server sent no CertificateVerify")
	}

	expectedFinished := hqgotlsclientkeys.TLS13FinishedVerify(schedule.FinishedKey(schedule.ServerHandshakeSecret), c.transcript, hashName)
	if subtle.ConstantTimeCompare(serverFinished, expectedFinished) != 1 {
		return hqgoerrors.Wrap(ErrVerifyFailed, "server Finished verify_data mismatch")
	}

	c.transcript = append(c.transcript, serverFinishedRaw...)

	clientAppSecret, serverAppSecret := schedule.ApplicationSecrets(c.transcript)

	c.logTrafficSecret("CLIENT_TRAFFIC_SECRET_0", hello.random, clientAppSecret)
	c.logTrafficSecret("SERVER_TRAFFIC_SECRET_0", hello.random, serverAppSecret)

	clientHandshakeKey, clientHandshakeIV, err := schedule.TrafficKey(schedule.ClientHandshakeSecret, &serverHello.suite)
	if err != nil {
		return err
	}

	clientProtection, err := record.NewProtection(&serverHello.suite, VersionTLS13, nil, clientHandshakeKey, clientHandshakeIV, true)
	if err != nil {
		return err
	}

	c.out.Protection = clientProtection

	if certRequest != nil {
		if err := c.sendClientCertificateTLS13(certRequest); err != nil {
			return err
		}
	}

	clientVerify := hqgotlsclientkeys.TLS13FinishedVerify(schedule.FinishedKey(schedule.ClientHandshakeSecret), c.transcript, hashName)

	if err = c.writeHandshakeMessage(HandshakeFinished, clientVerify); err != nil {
		return hqgoerrors.Wrap(err, "writing client Finished")
	}

	clientAppKey, clientAppIV, err := schedule.TrafficKey(clientAppSecret, &serverHello.suite)
	if err != nil {
		return err
	}

	serverAppKey, serverAppIV, err := schedule.TrafficKey(serverAppSecret, &serverHello.suite)
	if err != nil {
		return err
	}

	clientAppProtection, err := record.NewProtection(&serverHello.suite, VersionTLS13, nil, clientAppKey, clientAppIV, true)
	if err != nil {
		return err
	}

	serverAppProtection, err := record.NewProtection(&serverHello.suite, VersionTLS13, nil, serverAppKey, serverAppIV, true)
	if err != nil {
		return err
	}

	c.out.Protection = clientAppProtection
	c.in.Protection = serverAppProtection

	c.withState(func(state *ConnectionState) {
		state.HandshakeComplete = true
		state.NegotiatedProtocol = negotiatedALPN
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

// tls13CertificateRequest is the parsed TLS 1.3 CertificateRequest.
type tls13CertificateRequest struct {
	context                []byte
	signatureAlgorithms    []uint16
	certificateAuthorities [][]byte
}

// tls13CertificateVerify is the parsed TLS 1.3 CertificateVerify.
type tls13CertificateVerify struct {
	algorithm uint16
	signature []byte
}

// parseTLS13EncryptedExtensions parses EncryptedExtensions and returns the
// negotiated ALPN protocol.
func parseTLS13EncryptedExtensions(body []byte) (alpn string, err error) {
	r := message.NewReader(body)
	extensionsRaw := r.Vector16()

	extensions, err := parseExtensions(extensionsRaw)
	if err != nil {
		return "", err
	}

	for _, extension := range extensions {
		if extension.Type != extensionALPN {
			continue
		}

		ext := message.NewReader(extension.Data)
		list := ext.Vector16()
		protocols := message.NewReader(list)

		for protocols.Remaining() > 0 {
			protocol := string(protocols.Vector8())
			if alpn == "" {
				alpn = protocol
			}
		}
	}

	return alpn, nil
}

// parseTLS13CertificateRequest parses a TLS 1.3 CertificateRequest.
func parseTLS13CertificateRequest(body []byte) (request *tls13CertificateRequest, err error) {
	request = &tls13CertificateRequest{}

	r := message.NewReader(body)
	request.context = append([]byte(nil), r.Vector8()...)

	extensionsRaw := r.Vector16()

	extensions, err := parseExtensions(extensionsRaw)
	if err != nil {
		return nil, err
	}

	for _, extension := range extensions {
		switch extension.Type {
		case extensionSignatureAlgorithms:
			ext := message.NewReader(extension.Data)
			algorithms := ext.Vector16()
			reader := message.NewReader(algorithms)

			for reader.Remaining() >= 2 {
				request.signatureAlgorithms = append(request.signatureAlgorithms, reader.Uint16())
			}
		case 47: // certificate_authorities
			ext := message.NewReader(extension.Data)
			authorities := ext.Vector16()
			reader := message.NewReader(authorities)

			for reader.Remaining() > 0 {
				request.certificateAuthorities = append(request.certificateAuthorities, append([]byte(nil), reader.Vector16()...))
			}
		}
	}

	return request, nil
}

// parseTLS13CertificateVerify parses a TLS 1.3 CertificateVerify.
func parseTLS13CertificateVerify(body []byte) (verify *tls13CertificateVerify, err error) {
	r := message.NewReader(body)

	verify = &tls13CertificateVerify{
		algorithm: r.Uint16(),
		signature: append([]byte(nil), r.Vector16()...),
	}

	if err := r.Error(); err != nil {
		return nil, err
	}

	return verify, nil
}

// tls13CertificateVerifyInput builds the signed content of a TLS 1.3
// CertificateVerify message.
func tls13CertificateVerifyInput(contextString, hashName string, transcript []byte) (signed []byte) {
	hash := hqgotlsclientkeys.TranscriptHash(hashName, transcript)

	signed = make([]byte, 0, 64+len(contextString)+1+len(hash))
	for range 64 {
		signed = append(signed, 0x20)
	}

	signed = append(signed, contextString...)
	signed = append(signed, 0)
	signed = append(signed, hash...)

	return signed
}

// sendClientCertificateTLS13 sends the client Certificate and
// CertificateVerify messages when the server requested them.
func (c *Conn) sendClientCertificateTLS13(request *tls13CertificateRequest) (err error) {
	var certificate *Certificate

	requestInfo := &certificateRequestInfo{
		signatureAlgorithms: request.signatureAlgorithms,
	}

	if c.config.GetClientCertificate != nil {
		certificate, err = c.config.GetClientCertificate(&CertificateRequestInfo{
			AcceptableCAs:    request.certificateAuthorities,
			SignatureSchemes: schemesFromIDs(request.signatureAlgorithms),
			Version:          VersionTLS13,
		})
		if err != nil {
			return hqgoerrors.Wrap(err, "GetClientCertificate")
		}
	} else if len(c.config.Certificates) > 0 {
		certificate = &c.config.Certificates[0]
	}

	body, _ := message.AppendVector8(nil, request.context)

	if certificate == nil || len(certificate.Certificate) == 0 {
		body, _ = message.AppendVector24(body, nil)

		return c.writeHandshakeMessage(HandshakeCertificate, body)
	}

	var list []byte

	for _, der := range certificate.Certificate {
		entry, _ := message.AppendVector24(nil, der)
		entry, _ = message.AppendVector16(entry, nil)
		list = append(list, entry...)
	}

	body, _ = message.AppendVector24(body, list)

	if err = c.writeHandshakeMessage(HandshakeCertificate, body); err != nil {
		return hqgoerrors.Wrap(err, "writing client Certificate")
	}

	signature, algorithm, err := signCertificateVerify(certificate, c.transcript, VersionTLS13, requestInfo)
	if err != nil {
		return err
	}

	verifyBody := message.AppendUint16(nil, algorithm)
	verifyBody, _ = message.AppendVector16(verifyBody, signature)

	if err = c.writeHandshakeMessage(HandshakeCertificateVerify, verifyBody); err != nil {
		return hqgoerrors.Wrap(err, "writing CertificateVerify")
	}

	return nil
}
