package masque

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	quic "github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	"github.com/daeuniverse/quic-go/quicvarint"
)

// tcpConn adapts an established HTTP/3 CONNECT stream to net.Conn.
type tcpConn struct {
	http3.RequestStream
	localAddr  net.Addr
	remoteAddr net.Addr

	// respOnce guards the lazy CONNECT-response validation performed by an
	// optimistic dial (see Client.DialContext). responseValidated is set when
	// the dial already read (and checked) the response, as the strict dial
	// does. cli is set for optimistic dials, so a proxy that rejected the
	// 0-RTT early data can be reacted to here.
	respOnce          sync.Once
	respErr           error
	responseValidated bool
	cli               *Client
}

// awaitConnectResponse validates the proxy's CONNECT response before any
// tunneled data is returned. A dial may be optimistic, in which case the
// response is still in flight when DialContext returns and the status is only
// known here: a rejected target surfaces as a read error rather than a dial
// error.
func (c *tcpConn) awaitConnectResponse() error {
	if c.responseValidated {
		return nil
	}
	c.respOnce.Do(func() {
		rsp, err := c.RequestStream.ReadResponse()
		if err != nil {
			// A proxy that refuses the early data kills the connection; turn
			// 0-RTT off so the caller's next dial is a plain one instead of
			// hitting the same rejection again.
			if c.cli != nil {
				c.cli.abandonEarlyData(err)
			}
			c.respErr = fmt.Errorf("masque: read CONNECT response: %w", err)
			return
		}
		if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
			c.respErr = fmt.Errorf("masque: CONNECT rejected: %s", rsp.Status)
		}
	})
	return c.respErr
}

func (c *tcpConn) Read(p []byte) (int, error) {
	if err := c.awaitConnectResponse(); err != nil {
		return 0, err
	}
	return c.RequestStream.Read(p)
}

func (c *tcpConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *tcpConn) RemoteAddr() net.Addr { return c.remoteAddr }

// CloseWrite implements netproxy.CloseWriter. A quic-stream Close closes
// only the write direction — it sends a FIN to the peer and leaves the
// read side open — so the CONNECT server observes a clean half-close
// instead of a hard stream cancel, and response data still flows back.
// Without it the relay falls back to a read deadline and the server-side
// stream hangs until its own idle timeout.
func (c *tcpConn) CloseWrite() error { return c.RequestStream.Close() }

// Close ends the tunnel for good. It aborts the stream (RESET_STREAM +
// STOP_SENDING) rather than half-closing it: a FIN would leave the relay on
// the proxy waiting for the *target* to close its side — many long-lived
// targets never do — so every LAN connection closed this way leaves a zombie
// stream holding a slot in the peer's incoming-stream limit until the whole
// QUIC connection dies. A caller that wants the half-close semantics (FIN,
// keep reading) has CloseWrite.
func (c *tcpConn) Close() error {
	c.CancelRead(0)
	c.CancelWrite(0)
	return nil
}

var _ net.Conn = (*tcpConn)(nil)
var _ netproxy.CloseWriter = (*tcpConn)(nil)

// datagramMsg is one received UDP datagram on its way from a flow's read pump
// to ReadFrom. data is the pooled http3 receive buffer (release it after
// copying the payload out); payload is the tunneled UDP payload view (context
// id stripped); addr is the flow's target, allocated once per flow.
type datagramMsg struct {
	data    []byte
	payload []byte
	addr    *net.UDPAddr
	release func([]byte)
}

// udpFlow is one CONNECT-UDP stream bound to a fixed UDP target.
type udpFlow struct {
	target netip.AddrPort
	// udpAddr is the cached net.Addr for ReadFrom, so returning the source
	// address does not allocate.
	udpAddr *net.UDPAddr
	str     http3.RequestStream
	// release returns the pooled http3 receive buffer; nil when the http3
	// layer does not expose it.
	release func([]byte)
}

// destroy fully closes the flow's stream in both directions. CancelWrite
// alone (RESET_STREAM on the send side) is not enough: the peer keeps its
// side open until it tears the flow down itself, so the stream would keep
// occupying a slot in the peer's incoming-stream limit for the rest of the
// connection - one leaked DNS query at a time, until every dial blocks on
// the exhausted limit. CancelRead sends STOP_SENDING, which makes the peer
// reset its send side too and completes the stream.
func (f *udpFlow) destroy() {
	f.str.CancelRead(0)
	f.str.CancelWrite(0)
}

// openFlow establishes a CONNECT-UDP tunnel toward raddr.
func (c *Client) openFlow(ctx context.Context, raddr netip.AddrPort) (*udpFlow, error) {
	str, rsp, err := c.openConnectStream(ctx, "CONNECT-UDP", func() *http.Request {
		return &http.Request{
			Method: http.MethodConnect,
			Proto:  connectUDPProtocol,
			URL: &url.URL{
				Scheme: "https",
				Host:   c.authority,
				Path:   udpPath(raddr.Addr().String(), int(raddr.Port())),
			},
			Host: c.authority,
			Header: http.Header{
				"capsule-protocol": []string{"?1"},
			},
		}
	})
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		str.CancelWrite(0)
		return nil, fmt.Errorf("masque: CONNECT-UDP rejected: %s", rsp.Status)
	}
	flow := &udpFlow{target: raddr, udpAddr: net.UDPAddrFromAddrPort(raddr), str: str}
	// The http3 layer hands out pooled receive buffers without exposing the
	// release on its interface; use it when the concrete stream has it.
	if r, ok := str.(interface{ ReleaseDatagram([]byte) }); ok {
		flow.release = r.ReleaseDatagram
	}
	return flow, nil
}

// packetConn multiplexes UDP targets onto CONNECT-UDP streams of the shared
// H3 connection.
type packetConn struct {
	client *Client

	mu     sync.Mutex
	flows  map[netip.AddrPort]*udpFlow
	closed bool

	readCh chan datagramMsg
	ctx    context.Context
	cancel context.CancelFunc

	readDeadline  atomic.Int64 // unix nanos; 0 = no deadline
	writeDeadline atomic.Int64

	// Write path state, guarded by writeMu: the reusable context-id buffer,
	// one timer and one result channel, so a write carrying a deadline does
	// not allocate. Only one WriteTo runs at a time (the deadline machinery
	// assumes it).
	writeMu sync.Mutex
	wbuf    []byte
	wtimer  *time.Timer
	wres    chan error
	// rtimer is reused across reads carrying a deadline; a PacketConn is read
	// by a single consumer at a time.
	rtimer *time.Timer
}

var _ net.PacketConn = (*packetConn)(nil)

func (pc *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := pc.read(p)
	if err != nil {
		return 0, nil, err
	}
	return n, addr, nil
}

// ReadFromAddrPort is the allocation-free form of ReadFrom.
func (pc *packetConn) ReadFromAddrPort(p []byte) (int, netip.AddrPort, error) {
	n, addr, err := pc.read(p)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, addr.AddrPort(), nil
}

func (pc *packetConn) read(p []byte) (int, *net.UDPAddr, error) {
	var timeout <-chan time.Time
	if d := pc.readDeadline.Load(); d != 0 {
		deadline := time.Unix(0, d)
		if pc.rtimer == nil {
			pc.rtimer = time.NewTimer(time.Until(deadline))
		} else {
			stopAndDrain(pc.rtimer)
			pc.rtimer.Reset(time.Until(deadline))
		}
		timeout = pc.rtimer.C
	}
	select {
	case d, ok := <-pc.readCh:
		if !ok {
			return 0, nil, errMasqueClosed
		}
		if d.release != nil {
			defer d.release(d.data)
		}
		n := copy(p, d.payload)
		return n, d.addr, nil
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	case <-pc.ctx.Done():
		// Cancel does not close readCh, so wake the reader here instead of
		// leaving it blocked on a dead conn.
		return 0, nil, errMasqueClosed
	}
}

// stopAndDrain makes a reused timer safe to Reset: one that already fired
// must have its value drained first.
func stopAndDrain(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func (pc *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var ap netip.AddrPort
	switch a := addr.(type) {
	case *net.UDPAddr:
		ap = a.AddrPort()
	case *net.TCPAddr:
		ap = a.AddrPort()
	default:
		udp, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return 0, fmt.Errorf("masque: target must be a UDP address, got %T", addr)
		}
		ap = udp.AddrPort()
	}
	return pc.WriteToAddrPort(p, ap)
}

// WriteToAddrPort is the allocation-free form of WriteTo.
func (pc *packetConn) WriteToAddrPort(p []byte, addr netip.AddrPort) (int, error) {
	if len(p) > maxDatagramSize {
		return 0, fmt.Errorf("masque: datagram exceeds %d bytes", maxDatagramSize)
	}
	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	flow, err := pc.flow(addr)
	if err != nil {
		return 0, err
	}
	// RFC 9298 section 4: HTTP datagram payload = context id + UDP payload.
	// Context id 0 is a single zero byte; wbuf is reused across writes.
	pc.wbuf = append(pc.wbuf[:0], 0)
	pc.wbuf = append(pc.wbuf, p...)

	var timeout <-chan time.Time
	if d := pc.writeDeadline.Load(); d != 0 {
		deadline := time.Unix(0, d)
		if pc.wtimer == nil {
			pc.wtimer = time.NewTimer(time.Until(deadline))
		} else {
			stopAndDrain(pc.wtimer)
			pc.wtimer.Reset(time.Until(deadline))
		}
		timeout = pc.wtimer.C
		if pc.wres == nil {
			pc.wres = make(chan error, 1)
		}
		// Drop the result of an earlier abandoned write, if any.
		select {
		case <-pc.wres:
		default:
		}
		go func() { pc.wres <- flow.str.SendDatagram(pc.wbuf) }()
	}

	// Send without a deadline inline; with one, race the send against the
	// deadline. (A plain select-with-default here would fall through
	// immediately and silently drop the datagram.)
	var sendErr error
	if timeout == nil {
		sendErr = flow.str.SendDatagram(pc.wbuf)
	} else {
		select {
		case err := <-pc.wres:
			sendErr = err
		case <-timeout:
			sendErr = os.ErrDeadlineExceeded
			// The abandoned sender still references wbuf; force the next
			// write onto a fresh buffer instead of racing it.
			pc.wbuf = nil
		}
	}
	if sendErr == nil {
		return len(p), nil
	}
	pc.dropFlow(addr)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(sendErr, &tooLarge) {
		// The budget is min(peer's max_datagram_frame_size, the current
		// path MTU estimate); the latter grows as QUIC path MTU discovery
		// completes. Report it so the operator can see the path's real
		// capability (and whether the link's mtu= parameter is worth
		// setting) instead of guessing.
		return 0, fmt.Errorf("masque: datagram of %d bytes exceeds the tunnel budget of %d bytes (budget grows as QUIC path MTU discovery completes; measure the path before raising the link's mtu=)", len(p), tooLarge.MaxDataLen-2)
	}
	if errors.Is(sendErr, os.ErrDeadlineExceeded) {
		return 0, sendErr
	}
	return 0, fmt.Errorf("masque: send datagram: %w", sendErr)
}

// flow returns (and lazily establishes) the CONNECT-UDP stream for raddr.
// flow returns (and lazily establishes) the CONNECT-UDP stream for raddr.
// Called with writeMu held.
func (pc *packetConn) flow(raddr netip.AddrPort) (*udpFlow, error) {
	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		return nil, errMasqueClosed
	}
	if f, ok := pc.flows[raddr]; ok {
		pc.mu.Unlock()
		return f, nil
	}
	if len(pc.flows) >= maxUDPFlows {
		pc.mu.Unlock()
		return nil, fmt.Errorf("masque: too many UDP flows (%d)", maxUDPFlows)
	}
	pc.mu.Unlock()

	flow, err := pc.client.openFlow(pc.ctx, raddr)
	if err != nil {
		return nil, err
	}

	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		flow.destroy()
		return nil, errMasqueClosed
	}
	if existing, ok := pc.flows[raddr]; ok { // raced with a concurrent open
		pc.mu.Unlock()
		flow.destroy()
		return existing, nil
	}
	pc.flows[raddr] = flow
	pc.mu.Unlock()

	go pc.flowReadLoop(flow)
	return flow, nil
}

// flowReadLoop pumps HTTP datagrams from one CONNECT-UDP stream.
func (pc *packetConn) flowReadLoop(flow *udpFlow) {
	for {
		buf, err := flow.str.ReceiveDatagram(pc.ctx)
		if err != nil {
			pc.dropFlow(flow.target)
			return
		}
		contextID, consumed, err := quicvarint.Parse(buf)
		if err != nil {
			flow.release(buf)
			pc.dropFlow(flow.target)
			return
		}
		if contextID != 0 || len(buf) == consumed {
			// Unknown context (RFC 9298: drop, not fail) or empty payload.
			flow.release(buf)
			continue
		}
		// Hand the pooled buffer to the reader, who releases it after copying
		// the payload out; nothing on this path allocates.
		msg := datagramMsg{data: buf, payload: buf[consumed:], addr: flow.udpAddr, release: flow.release}
		select {
		case pc.readCh <- msg:
		case <-pc.ctx.Done():
			flow.release(buf)
			return
		}
	}
}

func (pc *packetConn) dropFlow(key netip.AddrPort) {
	pc.mu.Lock()
	flow, ok := pc.flows[key]
	delete(pc.flows, key)
	pc.mu.Unlock()
	if ok {
		flow.destroy()
	}
}

func (pc *packetConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (pc *packetConn) SetDeadline(t time.Time) error {
	pc.SetReadDeadline(t)
	pc.SetWriteDeadline(t)
	return nil
}

func (pc *packetConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		pc.readDeadline.Store(0)
	} else {
		pc.readDeadline.Store(t.UnixNano())
	}
	return nil
}

func (pc *packetConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		pc.writeDeadline.Store(0)
	} else {
		pc.writeDeadline.Store(t.UnixNano())
	}
	return nil
}

func (pc *packetConn) Close() error {
	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		return nil
	}
	pc.closed = true
	flows := make([]*udpFlow, 0, len(pc.flows))
	for _, f := range pc.flows {
		flows = append(flows, f)
	}
	pc.flows = make(map[netip.AddrPort]*udpFlow)
	pc.mu.Unlock()
	for _, f := range flows {
		f.destroy()
	}
	pc.cancel()
	close(pc.readCh)
	return nil
}

var errMasqueClosed = errors.New("masque: packet conn closed")
