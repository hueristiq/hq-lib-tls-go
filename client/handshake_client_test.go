package client_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	hqgotlsclient "github.com/hueristiq/hq-lib-tls-go/client"
	hqgotlsfingerprint "github.com/hueristiq/hq-lib-tls-go/fingerprint"
	hqgotlstestcert "github.com/hueristiq/hq-lib-tls-go/internal/testcert"
)

func startServer(t *testing.T, version uint16, cipherSuites []uint16) (address string, stop func()) {
	t.Helper()

	return startServerWithCertificate(t, hqgotlstestcert.RSA(t), version, cipherSuites)
}

func startServerWithCertificate(t *testing.T, certificate tls.Certificate, version uint16, cipherSuites []uint16) (address string, stop func()) { //nolint:gocritic // certificate is a test fixture.
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   version,
		MaxVersion:   version,
		CipherSuites: cipherSuites,
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}

		defer func() { _ = connection.Close() }()

		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

		if handshakeErr := connection.(*tls.Conn).HandshakeContext(context.Background()); handshakeErr != nil {
			return
		}

		_, _ = connection.Write([]byte("hello"))
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()

		<-done
	}
}

func TestClientTLS12ECDHEGCM(t *testing.T) {
	t.Parallel()

	address, stop := startServer(t, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256})
	defer stop()

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS12,
		MaxVersion:         hqgotlsclient.VersionTLS12,
		CipherSuites:       []uint16{0xC02F},
	})
	if err != nil {
		for _, event := range client.HandshakeTrace() {
			t.Logf("trace: %s %s version=%#x bytes=%d", event.Direction, event.Name, event.Version, len(event.Raw))
		}

		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	state := client.ConnectionState()
	if state.Version != hqgotlsclient.VersionTLS12 {
		t.Fatalf("version = %#x, want TLS 1.2", state.Version)
	}

	if state.CipherSuite != 0xC02F {
		t.Fatalf("suite = %#x, want 0xc02f", state.CipherSuite)
	}

	buffer := make([]byte, 5)

	if _, err = io.ReadFull(client, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buffer) != "hello" {
		t.Fatalf("read %q", buffer)
	}

	trace := client.HandshakeTrace()
	if len(trace) == 0 {
		t.Fatal("empty handshake trace")
	}

	for _, event := range trace {
		if event.Name != "ClientHello" {
			continue
		}

		ja3, err := hqgotlsfingerprint.JA3(event.Raw)
		if err != nil {
			t.Fatalf("JA3 from trace: %v", err)
		}

		if ja3 == "" {
			t.Fatal("JA3 from trace is empty")
		}
	}
}

func TestClientTLS12ECDHECBC(t *testing.T) {
	t.Parallel()

	address, stop := startServer(t, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA})
	defer stop()

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS12,
		MaxVersion:         hqgotlsclient.VersionTLS12,
		CipherSuites:       []uint16{0xC013},
	})
	if err != nil {
		for _, event := range client.HandshakeTrace() {
			t.Logf("trace: %s %s bytes=%d", event.Direction, event.Name, len(event.Raw))

			if event.Name == "ServerHello" || (event.Name == "ClientHello" && event.Direction == hqgotlsclient.Sent) {
				t.Logf("%s %s: %x", event.Direction, event.Name, event.Raw)
			}
		}

		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	if state := client.ConnectionState(); state.CipherSuite != 0xC013 {
		t.Fatalf("suite = %#x, want 0xc013", state.CipherSuite)
	}

	buffer := make([]byte, 5)

	if _, err = io.ReadFull(client, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}
}

type lockedBuffer struct {
	mutex sync.Mutex
	value bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (n int, err error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	return b.value.Write(p)
}

func (b *lockedBuffer) String() (value string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	return b.value.String()
}

func TestTLS12MasterSecretMatchesStdlib(t *testing.T) {
	t.Parallel()

	serverLog := &lockedBuffer{}
	clientLog := &lockedBuffer{}

	certificate := hqgotlstestcert.RSA(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{ //nolint:gosec // G402: the test pins TLS 1.2.
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		KeyLogWriter: serverLog,
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}

		defer func() { _ = connection.Close() }()

		_ = connection.(*tls.Conn).HandshakeContext(context.Background())
	}()

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", listener.Addr().String(), &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS12,
		MaxVersion:         hqgotlsclient.VersionTLS12,
		CipherSuites:       []uint16{0xC02F},
		KeyLogWriter:       clientLog,
	})
	if err == nil {
		_ = client.Close()
	}

	_ = listener.Close()

	<-done

	serverFields := strings.Fields(serverLog.String())
	clientFields := strings.Fields(clientLog.String())

	if len(serverFields) < 3 || len(clientFields) < 3 {
		t.Fatalf("missing key log lines:\nserver=%q\nclient=%q", serverLog.String(), clientLog.String())
	}

	if serverFields[1] != clientFields[1] {
		t.Fatalf("client random differs: server=%s client=%s", serverFields[1], clientFields[1])
	}

	if serverFields[2] != clientFields[2] {
		t.Fatalf("master secret differs: server=%s client=%s", serverFields[2], clientFields[2])
	}
}

func TestClientTLS12SuiteMatrix(t *testing.T) {
	t.Parallel()

	rsaCertificate := hqgotlstestcert.RSA(t)
	ecdsaCertificate := hqgotlstestcert.ECDSA(t)

	tests := []struct {
		name  string
		cert  tls.Certificate
		suite uint16
	}{
		{"ecdh-rsa-aes128-gcm", rsaCertificate, 0xC02F},
		{"ecdh-rsa-aes256-gcm", rsaCertificate, 0xC030},
		{"ecdh-rsa-aes128-cbc", rsaCertificate, 0xC013},
		{"ecdh-rsa-chacha", rsaCertificate, 0xCCA8},
		{"ecdh-ecdsa-aes128-gcm", ecdsaCertificate, 0xC02B},
		{"ecdh-ecdsa-aes256-gcm", ecdsaCertificate, 0xC02C},
		{"ecdh-ecdsa-chacha", ecdsaCertificate, 0xCCA9},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			address, stop := startServerWithCertificate(t, test.cert, tls.VersionTLS12, []uint16{test.suite})
			defer stop()

			client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
				InsecureSkipVerify: true,
				MinVersion:         hqgotlsclient.VersionTLS12,
				MaxVersion:         hqgotlsclient.VersionTLS12,
				CipherSuites:       []uint16{test.suite},
			})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}

			defer func() { _ = client.Close() }()

			if state := client.ConnectionState(); state.CipherSuite != test.suite {
				t.Fatalf("suite = %#x, want %#x", state.CipherSuite, test.suite)
			}

			buffer := make([]byte, 5)
			if _, err = io.ReadFull(client, buffer); err != nil {
				t.Fatalf("read: %v", err)
			}
		})
	}
}

func TestClientTLS13SuiteMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		suite uint16
	}{
		{"aes128-gcm", 0x1301},
		{"aes256-gcm", 0x1302},
		{"chacha", 0x1303},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			address, stop := startServer(t, tls.VersionTLS13, []uint16{test.suite})
			defer stop()

			client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
				InsecureSkipVerify: true,
				MinVersion:         hqgotlsclient.VersionTLS13,
				MaxVersion:         hqgotlsclient.VersionTLS13,
				CipherSuites:       []uint16{test.suite},
			})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}

			defer func() { _ = client.Close() }()

			if state := client.ConnectionState(); state.CipherSuite != test.suite {
				t.Fatalf("suite = %#x, want %#x", state.CipherSuite, test.suite)
			}

			buffer := make([]byte, 5)
			if _, err = io.ReadFull(client, buffer); err != nil {
				t.Fatalf("read: %v", err)
			}
		})
	}
}

func TestClientTLS13CustomClientHelloSpec(t *testing.T) {
	t.Parallel()

	address, stop := startServer(t, tls.VersionTLS13, []uint16{tls.TLS_AES_128_GCM_SHA256})
	defer stop()

	spec := &hqgotlsclient.HelloSpec{
		TLSVersMin:   hqgotlsclient.VersionTLS12,
		TLSVersMax:   hqgotlsclient.VersionTLS13,
		CipherSuites: []uint16{0x1301},
		GREASE:       true,
		Extensions: []hqgotlsclient.Extension{
			hqgotlsclient.SupportedVersionsExtension{Versions: []uint16{hqgotlsclient.VersionTLS13, hqgotlsclient.VersionTLS12}},
			hqgotlsclient.SupportedGroupsExtension{Groups: []hqgotlsclient.CurveID{tls.X25519}},
			hqgotlsclient.SignatureAlgorithmsExtension{Algorithms: []hqgotlsclient.SignatureScheme{tls.PSSWithSHA256, tls.PKCS1WithSHA256}},
			hqgotlsclient.KeyShareExtension{},
		},
	}

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS12,
		MaxVersion:         hqgotlsclient.VersionTLS13,
		ClientHelloSpec:    spec,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	if state := client.ConnectionState(); state.Version != hqgotlsclient.VersionTLS13 {
		t.Fatalf("version = %#x, want TLS 1.3", state.Version)
	}
}

func TestClientTLS13HelloRetryRequest(t *testing.T) {
	t.Parallel()

	certificate := hqgotlstestcert.RSA(t)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:     []tls.Certificate{certificate},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256},
		CurvePreferences: []tls.CurveID{tls.CurveP521},
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}

		defer func() { _ = connection.Close() }()

		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

		if handshakeErr := connection.(*tls.Conn).HandshakeContext(context.Background()); handshakeErr != nil {
			return
		}

		_, _ = connection.Write([]byte("hello"))
	}()

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", listener.Addr().String(), &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS13,
		MaxVersion:         hqgotlsclient.VersionTLS13,
		CipherSuites:       []uint16{0x1301},
		CurvePreferences:   []hqgotlsclient.CurveID{tls.X25519, tls.CurveP521},
		KeyShareGroups:     []hqgotlsclient.CurveID{tls.X25519},
	})
	if err != nil {
		for _, event := range client.HandshakeTrace() {
			t.Logf("trace: %s %s bytes=%d", event.Direction, event.Name, len(event.Raw))

			if event.Name == "ServerHello" || (event.Name == "ClientHello" && event.Direction == hqgotlsclient.Sent) {
				t.Logf("%s %s: %x", event.Direction, event.Name, event.Raw)
			}
		}

		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	buffer := make([]byte, 5)
	if _, err = io.ReadFull(client, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}

	_ = listener.Close()

	<-done
}

func TestClientTLS11(t *testing.T) {
	t.Setenv("GODEBUG", "tls10server=1")

	address, stop := startServer(t, tls.VersionTLS11, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA})
	defer stop()

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS11,
		MaxVersion:         hqgotlsclient.VersionTLS11,
		CipherSuites:       []uint16{0xC013},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	if state := client.ConnectionState(); state.Version != hqgotlsclient.VersionTLS11 {
		t.Fatalf("version = %#x, want TLS 1.1", state.Version)
	}

	buffer := make([]byte, 5)
	if _, err = io.ReadFull(client, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestClientTLS12RSAKeyExchange(t *testing.T) {
	t.Setenv("GODEBUG", "tlsrsakex=1")

	address, stop := startServer(t, tls.VersionTLS12, []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA})
	defer stop()

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS12,
		MaxVersion:         hqgotlsclient.VersionTLS12,
		CipherSuites:       []uint16{0x002F},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	if state := client.ConnectionState(); state.CipherSuite != 0x002F {
		t.Fatalf("suite = %#x, want 0x002f", state.CipherSuite)
	}

	buffer := make([]byte, 5)
	if _, err = io.ReadFull(client, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestClientTLS13ECDSA(t *testing.T) {
	t.Parallel()

	address, stop := startServerWithCertificate(t, hqgotlstestcert.ECDSA(t), tls.VersionTLS13, []uint16{0x1301})
	defer stop()

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS13,
		MaxVersion:         hqgotlsclient.VersionTLS13,
		CipherSuites:       []uint16{0x1301},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	buffer := make([]byte, 5)
	if _, err = io.ReadFull(client, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func startServerWithClientAuth(t *testing.T, version uint16, cipherSuites []uint16) (address string, stop func()) {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{hqgotlstestcert.RSA(t)},
		MinVersion:   version,
		MaxVersion:   version,
		CipherSuites: cipherSuites,
		ClientAuth:   tls.RequireAnyClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}

		defer func() { _ = connection.Close() }()

		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

		if handshakeErr := connection.(*tls.Conn).HandshakeContext(context.Background()); handshakeErr != nil {
			t.Logf("server handshake error: %v", handshakeErr)

			return
		}

		_, _ = connection.Write([]byte("hello"))
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()

		<-done
	}
}

func TestClientCertificateTLS12(t *testing.T) {
	t.Parallel()

	address, stop := startServerWithClientAuth(t, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256})
	defer stop()

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS12,
		MaxVersion:         hqgotlsclient.VersionTLS12,
		CipherSuites:       []uint16{0xC02F},
		Certificates:       []hqgotlsclient.Certificate{hqgotlstestcert.RSA(t)},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	buffer := make([]byte, 5)
	if _, err = io.ReadFull(client, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestClientCertificateTLS13(t *testing.T) {
	t.Parallel()

	address, stop := startServerWithClientAuth(t, tls.VersionTLS13, []uint16{tls.TLS_AES_128_GCM_SHA256})
	defer stop()

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS13,
		MaxVersion:         hqgotlsclient.VersionTLS13,
		CipherSuites:       []uint16{0x1301},
		Certificates:       []hqgotlsclient.Certificate{hqgotlstestcert.RSA(t)},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	buffer := make([]byte, 5)
	if _, err = io.ReadFull(client, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestConnConcurrentHandshake(t *testing.T) {
	t.Parallel()

	address, stop := startServer(t, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256})
	defer stop()

	raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}

	conn := hqgotlsclient.NewConn(raw, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS12,
		MaxVersion:         hqgotlsclient.VersionTLS12,
		CipherSuites:       []uint16{0xC02F},
	})

	var waitGroup sync.WaitGroup

	errors := make(chan error, 2)

	for range 2 {
		waitGroup.Add(1)

		go func() {
			defer waitGroup.Done()

			errors <- conn.Handshake()
		}()
	}

	waitGroup.Wait()
	close(errors)

	for handshakeErr := range errors {
		if handshakeErr != nil {
			t.Fatalf("Handshake() error = %v", handshakeErr)
		}
	}

	if _, err = io.ReadFull(conn, make([]byte, 5)); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestClientTLS10(t *testing.T) {
	t.Setenv("GODEBUG", "tls10server=1")

	address, stop := startServer(t, tls.VersionTLS10, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA})
	defer stop()

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS10,
		MaxVersion:         hqgotlsclient.VersionTLS10,
		CipherSuites:       []uint16{0xC013},
	})
	if err != nil {
		for _, event := range client.HandshakeTrace() {
			t.Logf("trace: %s %s bytes=%d", event.Direction, event.Name, len(event.Raw))

			if event.Name == "ServerHello" || (event.Name == "ClientHello" && event.Direction == hqgotlsclient.Sent) {
				t.Logf("%s %s: %x", event.Direction, event.Name, event.Raw)
			}
		}

		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	if state := client.ConnectionState(); state.Version != hqgotlsclient.VersionTLS10 {
		t.Fatalf("version = %#x, want TLS 1.0", state.Version)
	}

	buffer := make([]byte, 5)

	if _, err = io.ReadFull(client, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestClientTLS13(t *testing.T) {
	t.Parallel()

	address, stop := startServer(t, tls.VersionTLS13, []uint16{tls.TLS_AES_128_GCM_SHA256})
	defer stop()

	client, err := hqgotlsclient.DialContext(context.Background(), "tcp", address, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS13,
		MaxVersion:         hqgotlsclient.VersionTLS13,
		CipherSuites:       []uint16{0x1301},
	})
	if err != nil {
		for _, event := range client.HandshakeTrace() {
			t.Logf("trace: %s %s bytes=%d", event.Direction, event.Name, len(event.Raw))

			if event.Name == "ServerHello" || (event.Name == "ClientHello" && event.Direction == hqgotlsclient.Sent) {
				t.Logf("%s %s: %x", event.Direction, event.Name, event.Raw)
			}
		}

		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	state := client.ConnectionState()
	if state.Version != hqgotlsclient.VersionTLS13 {
		t.Fatalf("version = %#x, want TLS 1.3", state.Version)
	}

	if state.CipherSuite != 0x1301 {
		t.Fatalf("suite = %#x, want 0x1301", state.CipherSuite)
	}

	buffer := make([]byte, 5)

	if _, err = io.ReadFull(client, buffer); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buffer) != "hello" {
		t.Fatalf("read %q", buffer)
	}

	trace := client.HandshakeTrace()
	if len(trace) == 0 {
		t.Fatal("empty handshake trace")
	}

	for _, event := range trace {
		if event.Name != "ClientHello" {
			continue
		}

		ja3, err := hqgotlsfingerprint.JA3(event.Raw)
		if err != nil {
			t.Fatalf("JA3 from trace: %v", err)
		}

		if ja3 == "" {
			t.Fatal("JA3 from trace is empty")
		}
	}
}

func TestDialHostPort(t *testing.T) {
	t.Parallel()

	address, stop := startServer(t, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256})
	defer stop()

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}

	client, err := hqgotlsclient.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second, &hqgotlsclient.Config{
		InsecureSkipVerify: true,
		MinVersion:         hqgotlsclient.VersionTLS12,
		MaxVersion:         hqgotlsclient.VersionTLS12,
		CipherSuites:       []uint16{0xC02F},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	_ = client.Close()
}
