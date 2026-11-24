package client

import (
	"context"
	"crypto/x509"
	"net"
	"sync"
	"time"

	"github.com/hueristiq/hq-lib-tls-go/client/internal/record"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// ContextDialer is the dialing interface accepted by DialWithDialerContext.
// It is satisfied by *net.Dialer and golang.org/x/net/proxy dialers.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Conn is a client TLS connection. The zero value is not usable; create one
// with NewConn, Dial, or one of the Dial variants.
type Conn struct {
	conn   net.Conn
	config *Config

	handshakeMu   sync.Mutex
	handshakeDone bool
	handshakeErr  error
	handshakeWait chan struct{}

	stateMu sync.RWMutex

	state ConnectionState
	trace *traceSink

	in  *record.State
	out *record.State

	handshakeBuf []byte
	transcript   []byte
}

// NewConn wraps an existing connection in a client. The handshake runs on the
// first call to Handshake or HandshakeContext, or on the first Read or Write.
func NewConn(conn net.Conn, config *Config) (client *Conn) {
	clone := config.Clone()
	if clone == nil {
		clone = &Config{}
	}

	client = &Conn{
		conn:   conn,
		config: clone,
	}

	client.trace = newTraceSink(clone)

	return client
}

// Dial connects to addr and performs a TLS handshake.
func Dial(network, addr string, config *Config) (conn *Conn, err error) {
	return DialWithDialerContext(context.Background(), &net.Dialer{}, network, addr, config)
}

// DialTimeout connects to addr with the given timeout and performs a TLS
// handshake.
func DialTimeout(network, addr string, timeout time.Duration, config *Config) (conn *Conn, err error) {
	dialer := &net.Dialer{Timeout: timeout}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return DialWithDialerContext(ctx, dialer, network, addr, config)
}

// DialContext connects to addr with ctx and performs a TLS handshake.
func DialContext(ctx context.Context, network, addr string, config *Config) (conn *Conn, err error) {
	return DialWithDialerContext(ctx, &net.Dialer{}, network, addr, config)
}

// DialWithDialer connects to addr through dialer and performs a TLS
// handshake.
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (conn *Conn, err error) {
	return DialWithDialerContext(context.Background(), dialer, network, addr, config)
}

// DialWithDialerContext connects to addr through dialer with ctx and
// performs a TLS handshake.
func DialWithDialerContext(ctx context.Context, dialer ContextDialer, network, addr string, config *Config) (conn *Conn, err error) {
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		err = hqgoerrors.Wrapf(err, "dialing %s", addr)

		return nil, err
	}

	client := NewConn(rawConn, config)

	if client.config.ServerName == "" {
		if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			client.config.ServerName = host
		}
	}

	if err = client.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()

		return client, err
	}

	return client, nil
}

// Handshake performs the TLS handshake.
func (c *Conn) Handshake() (err error) {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext performs the TLS handshake bounded by ctx. It is a no-op
// after a successful handshake and returns the original error after a failed
// one.
func (c *Conn) HandshakeContext(ctx context.Context) (err error) {
	if c == nil {
		return hqgoerrors.New("invalid input, Conn is nil")
	}

	c.handshakeMu.Lock()

	if c.handshakeDone {
		err = c.handshakeErr
		c.handshakeMu.Unlock()

		return err
	}

	if wait := c.handshakeWait; wait != nil {
		c.handshakeMu.Unlock()

		select {
		case <-wait:
			c.handshakeMu.Lock()
			err = c.handshakeErr
			c.handshakeMu.Unlock()

			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	wait := make(chan struct{})
	c.handshakeWait = wait
	c.handshakeMu.Unlock()

	err = c.config.Validate()
	if err == nil {
		if handshakeErr := c.clientHandshake(ctx); handshakeErr != nil {
			err = hqgoerrors.Join(ErrHandshake, handshakeErr)
		}
	}

	c.handshakeMu.Lock()
	c.handshakeErr = err
	c.handshakeDone = true
	c.handshakeWait = nil

	close(wait)
	c.handshakeMu.Unlock()

	return err
}

// withState updates the connection state under the state lock.
func (c *Conn) withState(update func(*ConnectionState)) {
	c.stateMu.Lock()
	update(&c.state)
	c.stateMu.Unlock()
}

// ConnectionState returns the negotiated state. Before a successful
// handshake the zero fields report that nothing was negotiated.
func (c *Conn) ConnectionState() (state ConnectionState) {
	if c == nil {
		return state
	}

	c.stateMu.RLock()
	state = c.state
	state.PeerCertificates = append([]*x509.Certificate(nil), c.state.PeerCertificates...)
	state.VerifiedChains = cloneChains(c.state.VerifiedChains)
	c.stateMu.RUnlock()

	return state
}

// HandshakeTrace returns a copy of the decrypted handshake events.
func (c *Conn) HandshakeTrace() (events []HandshakeEvent) {
	if c == nil || c.trace == nil {
		return nil
	}

	return c.trace.trace()
}

// HandshakeLog returns the accumulated handshake log.
func (c *Conn) HandshakeLog() (log *HandshakeLog) {
	if c == nil || c.trace == nil {
		return &HandshakeLog{}
	}

	return c.trace.log()
}

// Read reads application data. It runs the handshake first if necessary.
func (c *Conn) Read(b []byte) (n int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	return c.readApplicationData(b)
}

// Write writes application data. It runs the handshake first if necessary.
func (c *Conn) Write(b []byte) (n int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	return c.writeApplicationData(b)
}

// readApplicationData reads application records, handling alerts and
// post-handshake messages.
func (c *Conn) readApplicationData(b []byte) (n int, err error) {
	for {
		typ, payload, readErr := c.in.ReadRecord()
		if readErr != nil {
			return 0, readErr
		}

		switch typ {
		case record.TypeApplicationData:
			return copy(b, payload), nil
		case record.TypeAlert:
			return 0, alertFromPayload(payload)
		case record.TypeHandshake, record.TypeChangeCipherSpec:
			continue
		default:
			return 0, hqgoerrors.Errorf("unexpected record type %d", typ)
		}
	}
}

// writeApplicationData writes application records.
func (c *Conn) writeApplicationData(b []byte) (n int, err error) {
	for len(b) > 0 {
		chunk := b
		if len(chunk) > record.MaxPayload {
			chunk = chunk[:record.MaxPayload]
		}

		if err := c.out.WriteRecord(record.TypeApplicationData, chunk); err != nil {
			return n, err
		}

		n += len(chunk)
		b = b[len(chunk):]
	}

	return n, nil
}

// Close closes the underlying connection.
func (c *Conn) Close() (err error) {
	if c == nil || c.conn == nil {
		return nil
	}

	return c.conn.Close()
}

// CloseWrite closes the write side when the underlying connection supports
// it.
func (c *Conn) CloseWrite() (err error) {
	if c == nil || c.conn == nil {
		return nil
	}

	if closeWriter, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}

	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() (addr net.Addr) {
	if c == nil || c.conn == nil {
		return nil
	}

	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() (addr net.Addr) {
	if c == nil || c.conn == nil {
		return nil
	}

	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines.
func (c *Conn) SetDeadline(t time.Time) (err error) {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}

	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *Conn) SetReadDeadline(t time.Time) (err error) {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}

	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *Conn) SetWriteDeadline(t time.Time) (err error) {
	if c == nil || c.conn == nil {
		return net.ErrClosed
	}

	return c.conn.SetWriteDeadline(t)
}

// NetConn returns the underlying network connection.
func (c *Conn) NetConn() (conn net.Conn) {
	if c == nil {
		return nil
	}

	return c.conn
}

// cloneChains deep-copies verified chains.
func cloneChains(chains [][]*x509.Certificate) (clone [][]*x509.Certificate) {
	if chains == nil {
		return nil
	}

	clone = make([][]*x509.Certificate, len(chains))

	for i, chain := range chains {
		clone[i] = append([]*x509.Certificate(nil), chain...)
	}

	return clone
}
