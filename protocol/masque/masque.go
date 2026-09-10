// Package masque implements a MASQUE proxy client (RFC 9298 CONNECT-UDP and
// plain HTTP/3 CONNECT for TCP), riding on the utls-enabled quic-go fork so
// the whole tunnel presents an HTTP/3 + QUIC datagram traffic shape.
//
// TCP: a plain CONNECT request per target, stream body carries raw bytes.
// UDP: one extended CONNECT-UDP stream per target (context id 0), UDP
// payloads travel as RFC 9297 HTTP datagrams on the stream.
package masque

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	utls "github.com/refraction-networking/utls"
)

const (
	connectUDPProtocol = "connect-udp"
	udpPathPrefix      = "/.well-known/masque/udp/"

	maxDatagramSize = 1200
	maxUDPFlows     = 128
	idleTimeout     = 5 * time.Minute
)

// Client multiplexes TCP CONNECT streams and UDP CONNECT-UDP flows over a
// single HTTP/3 connection to a MASQUE proxy.
type Client struct {
	addr string // proxy "host:port"

	// authority is the value of the :authority pseudo header
	// (defaults to the proxy address).
	authority string

	tlsConf  *utls.Config
	quicConf *quic.Config

	// dialUDP provides the underlying UDP packet conn for QUIC. When nil,
	// a local UDP socket is created.
	dialUDP func(ctx context.Context, addr string) (net.PacketConn, error)

	mu     sync.Mutex
	conn   *http3.ClientConn
	closed bool
	alive  atomic.Bool
}

// Option customizes a Client.
type Option func(*Client)

// WithAuthority overrides the :authority pseudo header value.
func WithAuthority(authority string) Option {
	return func(c *Client) { c.authority = authority }
}

// WithPacketConnDialer routes the QUIC layer through the given packet conn
// factory, allowing MASQUE to be stacked on top of another UDP path.
func WithPacketConnDialer(fn func(ctx context.Context, addr string) (net.PacketConn, error)) Option {
	return func(c *Client) { c.dialUDP = fn }
}

// NewClient creates a MASQUE client targeting addr ("host:port").
func NewClient(addr string, sni string, allowInsecure bool, opts ...Option) (*Client, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("masque: invalid proxy address: %w", err)
	}
	if sni == "" {
		sni = host
	}
	c := &Client{
		addr:      addr,
		authority: addr,
		tlsConf: &utls.Config{
			ServerName:         sni,
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: allowInsecure,
		},
		quicConf: &quic.Config{
			MaxIdleTimeout:  idleTimeout,
			EnableDatagrams: true,
		},
		alive: atomic.Bool{},
	}
	c.alive.Store(true)
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// ensureConn lazily establishes the shared H3 connection.
func (c *Client) ensureConn(ctx context.Context) (*http3.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.conn != nil {
		return c.conn, nil
	}
	transport := &http3.Transport{
		TLSClientConfig: c.tlsConf,
		QUICConfig:      c.quicConf,
		EnableDatagrams: true,
	}
	var qconn quic.EarlyConnection
	if c.dialUDP != nil {
		pconn, err := c.dialUDP(ctx, c.addr)
		if err != nil {
			return nil, fmt.Errorf("masque: dial udp: %w", err)
		}
		udpAddr, err := net.ResolveUDPAddr("udp", c.addr)
		if err != nil {
			pconn.Close()
			return nil, fmt.Errorf("masque: resolve proxy: %w", err)
		}
		qt := &quic.Transport{Conn: pconn}
		qconn, err = qt.DialEarly(ctx, udpAddr, c.tlsConf, c.quicConf)
		if err != nil {
			pconn.Close()
			return nil, fmt.Errorf("masque: dial quic: %w", err)
		}
	} else {
		var err error
		qconn, err = quic.DialAddrEarly(ctx, c.addr, c.tlsConf, c.quicConf)
		if err != nil {
			return nil, fmt.Errorf("masque: dial quic: %w", err)
		}
	}
	c.conn = transport.NewClientConn(qconn)
	return c.conn, nil
}

// DialContext opens a TCP tunnel via a plain HTTP/3 CONNECT to address.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("masque: unsupported network %q, only tcp", network)
	}
	cc, err := c.ensureConn(ctx)
	if err != nil {
		return nil, err
	}
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("masque: open stream: %w", err)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: address},
		Host:   address,
	}
	if err := str.SendRequestHeader(req); err != nil {
		return nil, fmt.Errorf("masque: send CONNECT: %w", err)
	}
	rsp, err := str.ReadResponse()
	if err != nil {
		return nil, fmt.Errorf("masque: read CONNECT response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		str.CancelWrite(0)
		return nil, fmt.Errorf("masque: CONNECT rejected: %s", rsp.Status)
	}
	return &tcpConn{
		Stream:     str,
		localAddr:  &net.TCPAddr{},
		remoteAddr: &net.TCPAddr{},
	}, nil
}

// ListenPacket creates a UDP packet conn whose datagrams travel over
// per-target CONNECT-UDP streams on the shared H3 connection.
func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	pctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &packetConn{
		client: c,
		ctx:    pctx,
		cancel: cancel,
		flows:  make(map[string]*udpFlow),
		readCh: make(chan *datagram, maxUDPFlows*4),
	}, nil
}

// Close tears down the shared H3 connection (if any).
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.alive.Store(false)
	if c.conn != nil {
		return c.conn.CloseWithError(0, "client closed")
	}
	return nil
}

// Alive reports whether the client is usable.
func (c *Client) Alive() bool { return c.alive.Load() }

// udpPath builds the RFC 9298 CONNECT-UDP URI path for a target.
func udpPath(targetHost string, targetPort int) string {
	// RFC 9298 section 3.2: the host is percent-encoded (IPv6 colons, etc.).
	escaped := url.PathEscape(strings.Trim(targetHost, "[]"))
	// RFC 9298 section 3.2 percent-encodes the host: PathEscape leaves the
	// colon (a pchar) untouched, so IPv6 literals must be escaped by hand.
	escaped = strings.ReplaceAll(escaped, ":", "%3A")
	return udpPathPrefix + escaped + "/" + fmt.Sprint(targetPort) + "/"
}
