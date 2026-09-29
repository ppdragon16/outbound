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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
)

const (
	connectUDPProtocol = "connect-udp"
	udpPathPrefix      = "/.well-known/masque/udp/"

	// The inner connection's post-handshake datagrams (e.g. browser h3) run up
	// to ~1400 bytes; the tunnel carries up to ~1424 of them in a 1452-byte
	// outer packet (1452 minus QUIC, DATAGRAM-frame and datagram-context
	// headers). Larger datagrams cannot be relayed in one outer datagram; the
	// inner connection's path MTU discovery converges below this cap after
	// seeing the loss.
	maxDatagramSize = 1400
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

	// preferV2 offers QUIC v2 (RFC 9369) in the first packet, keeping v1 for
	// version-negotiation fallback.
	preferV2 bool

	// zeroRTT sends the CONNECT / CONNECT-UDP request as QUIC 0-RTT early
	// data on a resumed session. It is cleared for good when the proxy
	// refuses the early data (see abandonEarlyData).
	zeroRTT bool

	// strictConnect makes DialContext wait for the CONNECT response, so a
	// rejected target is reported as a dial error. See WithStrictConnect.
	strictConnect bool

	// congestionControl selects the QUIC congestion controller: "bbrv3"
	// (default) or "bbr" (BBRv1). "brutal" combined with a non-zero
	// bandwidth selects the fixed-rate Brutal sender. See
	// WithCongestionControl and WithBandwidth.
	congestionControl string

	// bandwidth is the Brutal target rate in Mbps; it only has an effect
	// when congestionControl is "brutal". Zero falls back to the fair-share
	// controller.
	bandwidth uint64

	// initialPacketSize is the QUIC Initial packet size (the path MTU budget
	// in use before discovery). Zero keeps the safe protocol default (1280),
	// which fits every path; a larger value (e.g. 1452 on a 1500-MTU path)
	// makes big datagrams deliverable immediately, but drops the handshake on
	// paths whose MTU cannot carry it. See WithMTU.
	initialPacketSize int

	mu   sync.Mutex
	conn *http3.ClientConn
	// qconn is the QUIC connection behind conn, kept so a connection that
	// died (idle timeout, server restart, path change) can be detected and
	// replaced instead of being handed out for every later dial.
	qconn  quic.Connection
	closed bool
	alive  atomic.Bool
}

// ccAddr returns the proxy address for the congestion controller's initial
// packet-size heuristic. An unresolvable host yields nil, which the controller
// treats as the minimum size.
func ccAddr(addr string) net.Addr {
	if ua, err := net.ResolveUDPAddr("udp", addr); err == nil {
		return ua
	}
	return nil
}

// Option customizes a Client.
type Option func(*Client)

// WithAuthority overrides the :authority pseudo header value.
func WithAuthority(authority string) Option {
	return func(c *Client) { c.authority = authority }
}

// WithQuicV2 offers QUIC v2 first (RFC 9369), with v1 kept for fallback.
func WithQuicV2(prefer bool) Option {
	return func(c *Client) { c.preferV2 = prefer }
}

// WithZeroRTT opts into QUIC 0-RTT: on a resumed session the first CONNECT or
// CONNECT-UDP request rides in early data, saving one round trip to the proxy.
//
// Early data is replayable by an observer, so this stays opt-in per outbound.
// It also needs the proxy to accept 0-RTT (quic.Config.Allow0RTT, which
// http3.Server enables by default); when the proxy refuses, the request is
// retried once on a fresh connection without early data.
func WithZeroRTT() Option {
	return func(c *Client) { c.zeroRTT = true }
}

// WithMTU sets the QUIC Initial packet size, i.e. the path MTU budget this
// client starts from (before MTU discovery). Use it when the path is known to
// carry 1500-byte datagrams (link parameter mtu=1452) so that datagrams up to
// the relay cap are deliverable from the first packet instead of after path
// MTU discovery converges.
//
// Leave it unset on unknown paths: an oversized Initial packet is dropped by
// any hop whose MTU is smaller and the handshake never completes
// ("timeout: no recent network activity").
func WithMTU(mtu int) Option {
	return func(c *Client) { c.initialPacketSize = mtu }
}

// WithStrictConnect makes DialContext wait for the proxy's CONNECT response
// before returning, so a rejected target (or an unreachable upstream) is
// reported as a dial error.
//
// The default is an optimistic dial: the CONNECT request is sent and
// DialContext returns immediately, with the response status validated on the
// first Read. The response only arrives after the proxy has dialed the target,
// so waiting for it serializes the QUIC handshake and the proxy's target dial
// into the dial path - two round trips where the other QUIC outbounds pay one
// (their connect is fire-and-forget). Optimistic dialing keeps the node latency
// a client measures comparable across protocols, at the cost of surfacing
// target rejections on first use instead of at dial time.
func WithStrictConnect() Option {
	return func(c *Client) { c.strictConnect = true }
}

// WithCongestionControl selects the congestion controller by name: "bbrv3"
// (the default, as for the other QUIC outbounds) or "bbr" (BBRv1); any other
// name falls back to BBRv3. Lossy long-RTT paths sometimes do better on BBRv1.
// "brutal" selects the fixed-rate Brutal sender, which requires WithBandwidth.
func WithCongestionControl(name string) Option {
	return func(c *Client) { c.congestionControl = name }
}

// WithBandwidth sets the Brutal target rate in Mbps (used only when the
// congestion controller is "brutal"). Zero keeps the fair-share controller.
func WithBandwidth(mbps uint64) Option {
	return func(c *Client) { c.bandwidth = mbps }
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
			// Match the other QUIC outbounds (tuic/juicity/hysteria2): BBRv3
			// from the first packet instead of quic-go's loss-sensitive
			// default, plus the netem-tuned receive windows and a keepalive.
			// Without these a long-RTT path with any loss collapses to a few
			// hundred kbit/s, which is exactly where a tunnel gets used.
			InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
			MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
			MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
			KeepAlivePeriod:                10 * time.Second,
		},
		alive: atomic.Bool{},
	}
	c.alive.Store(true)
	for _, opt := range opts {
		opt(c)
	}
	// Set after the options so WithCongestionControl/WithBandwidth are
	// honoured.
	switch {
	case c.congestionControl == "brutal" && c.bandwidth > 0:
		c.quicConf.InitialCongestionControl = congestion.NewBrutalSenderWithBandwidth(c.bandwidth)
	default:
		c.quicConf.InitialCongestionControl = congestion.NewInitialSender(c.congestionControl, ccAddr(addr))
	}

	if c.zeroRTT {
		// 0-RTT needs a session ticket to resume from; without a cache
		// DialEarly never resumes and the request is never sent early.
		c.tlsConf.ClientSessionCache = protocol.ZeroRTTSessionCache()
	}
	if c.initialPacketSize > 0 {
		c.quicConf.InitialPacketSize = uint16(c.initialPacketSize)
	}
	if c.preferV2 {
		c.quicConf.Versions = protocol.QuicVersions(protocol.Flags_Quic_PreferV2)
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
		if c.qconn == nil || c.qconn.Context().Err() == nil {
			return c.conn, nil
		}
		// The cached connection is gone: drop it and dial a fresh one. Keeping
		// it would fail every subsequent dial.
		c.conn, c.qconn = nil, nil
	}
	transport := &http3.Transport{
		TLSClientConfig: c.tlsConf,
		QUICConfig:      c.quicConf,
		EnableDatagrams: true,
	}
	var qconn quic.Connection
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
		if c.zeroRTT {
			qconn, err = qt.DialEarly(ctx, udpAddr, c.tlsConf, c.quicConf)
		} else {
			qconn, err = qt.Dial(ctx, udpAddr, c.tlsConf, c.quicConf)
		}
		if err != nil {
			pconn.Close()
			return nil, fmt.Errorf("masque: dial quic: %w", err)
		}
	} else {
		var err error
		if c.zeroRTT {
			qconn, err = quic.DialAddrEarly(ctx, c.addr, c.tlsConf, c.quicConf)
		} else {
			qconn, err = quic.DialAddr(ctx, c.addr, c.tlsConf, c.quicConf)
		}
		if err != nil {
			return nil, fmt.Errorf("masque: dial quic: %w", err)
		}
	}
	c.conn = transport.NewClientConn(qconn)
	c.qconn = qconn
	return c.conn, nil
}

// dropDeadConn clears the cached connection when its QUIC connection is gone
// and reports whether it dropped one. This closes the race where the
// connection dies between ensureConn's liveness check and a stream open.
func (c *Client) dropDeadConn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.qconn == nil || c.qconn.Context().Err() == nil {
		return false
	}
	c.conn, c.qconn = nil, nil
	return true
}

// openRequestStream opens a request stream on the shared connection, dialing a
// fresh connection once when the cached one turns out to be unusable.
func (c *Client) openRequestStream(ctx context.Context) (http3.RequestStream, error) {
	for attempt := 0; ; attempt++ {
		cc, err := c.ensureConn(ctx)
		if err != nil {
			return nil, err
		}
		str, err := cc.OpenRequestStream(ctx)
		if err == nil {
			return str, nil
		}
		if attempt == 0 && c.dropDeadConn() {
			continue
		}
		return nil, fmt.Errorf("masque: open stream: %w", err)
	}
}

// openConnectStream opens a CONNECT (op "CONNECT") or CONNECT-UDP (op
// "CONNECT-UDP") request stream on the shared H3 connection, sends req and
// waits for the response headers. The stream is left open for tunneling; the
// caller owns it and must cancel it if the response is not a success.
//
// When the proxy refuses the 0-RTT early data of the shared connection
// (quic.Err0RTTRejected), that connection is dropped and the request is
// retried once on a fresh connection that does not use early data.
func (c *Client) openConnectStream(ctx context.Context, op string, req func() *http.Request) (http3.RequestStream, *http.Response, error) {
	for attempt := 0; ; attempt++ {
		str, rsp, err := c.tryConnectStream(ctx, op, req)
		if err == nil {
			return str, rsp, nil
		}
		if attempt == 0 && c.abandonEarlyData(err) {
			continue
		}
		return nil, nil, err
	}
}

// tryConnectStream performs one request attempt on the current connection.
func (c *Client) tryConnectStream(ctx context.Context, op string, req func() *http.Request) (http3.RequestStream, *http.Response, error) {
	str, err := c.openRequestStream(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := str.SendRequestHeader(req()); err != nil {
		str.CancelWrite(0)
		return nil, nil, fmt.Errorf("masque: send %s: %w", op, err)
	}
	rsp, err := str.ReadResponse()
	if err != nil {
		str.CancelWrite(0)
		return nil, nil, fmt.Errorf("masque: read %s response: %w", op, err)
	}
	return str, rsp, nil
}

// abandonEarlyData turns 0-RTT off after the proxy refused the early data of
// the shared connection, and reports whether the caller should retry without
// early data. Turning it off also stops the other requests in flight on that
// rejected connection from all retrying: whoever observes the rejection first
// retries, the rest fail fast.
func (c *Client) abandonEarlyData(err error) bool {
	if !errors.Is(err, quic.Err0RTTRejected) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.zeroRTT {
		return false
	}
	c.zeroRTT = false
	if c.conn != nil {
		_ = c.conn.CloseWithError(0, "0-RTT rejected")
		c.conn, c.qconn = nil, nil
	}
	return true
}

// DialContext opens a TCP tunnel via a plain HTTP/3 CONNECT to address.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("masque: unsupported network %q, only tcp", network)
	}
	req := func() *http.Request {
		return &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: address},
			Host:   address,
		}
	}
	// Optimistic dial: send the CONNECT and return without waiting for the
	// response, which the proxy only sends after it has dialed the target.
	// tcpConn.Read validates the status before handing over any data, and
	// turns 0-RTT off if the proxy rejected the early data.
	if !c.strictConnect {
		str, err := c.openRequestStream(ctx)
		if err != nil {
			return nil, err
		}
		if err := str.SendRequestHeader(req()); err != nil {
			str.CancelWrite(0)
			return nil, fmt.Errorf("masque: send CONNECT: %w", err)
		}
		return &tcpConn{
			RequestStream: str,
			localAddr:     &net.TCPAddr{},
			remoteAddr:    &net.TCPAddr{},
			cli:           c,
		}, nil
	}
	str, rsp, err := c.openConnectStream(ctx, "CONNECT", req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		str.CancelWrite(0)
		return nil, fmt.Errorf("masque: CONNECT rejected: %s", rsp.Status)
	}
	return &tcpConn{
		RequestStream:     str,
		localAddr:         &net.TCPAddr{},
		remoteAddr:        &net.TCPAddr{},
		responseValidated: true,
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
		flows:  make(map[netip.AddrPort]*udpFlow),
		readCh: make(chan datagramMsg, maxUDPFlows*4),
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
