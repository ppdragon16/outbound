package masque

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/daeuniverse/quic-go/http3"
	"github.com/daeuniverse/quic-go/quicvarint"
)

// tcpConn adapts an established HTTP/3 CONNECT stream to net.Conn.
type tcpConn struct {
	http3.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *tcpConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *tcpConn) RemoteAddr() net.Addr { return c.remoteAddr }

var _ net.Conn = (*tcpConn)(nil)

// datagram is one received UDP payload and its originating target.
type datagram struct {
	payload []byte
	raddr   net.Addr
}

// udpFlow is one CONNECT-UDP stream bound to a fixed UDP target.
type udpFlow struct {
	target net.Addr
	str    http3.RequestStream
}

// openFlow establishes a CONNECT-UDP tunnel toward raddr.
func (c *Client) openFlow(ctx context.Context, raddr *net.UDPAddr) (*udpFlow, error) {
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
		Proto:  connectUDPProtocol,
		URL: &url.URL{
			Scheme: "https",
			Host:   c.authority,
			Path:   udpPath(raddr.IP.String(), raddr.Port),
		},
		Host: c.authority,
		Header: http.Header{
			"capsule-protocol": []string{"?1"},
		},
	}
	if err := str.SendRequestHeader(req); err != nil {
		return nil, fmt.Errorf("masque: send CONNECT-UDP: %w", err)
	}
	rsp, err := str.ReadResponse()
	if err != nil {
		return nil, fmt.Errorf("masque: read CONNECT-UDP response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		str.CancelWrite(0)
		return nil, fmt.Errorf("masque: CONNECT-UDP rejected: %s", rsp.Status)
	}
	return &udpFlow{target: raddr, str: str}, nil
}

// packetConn multiplexes UDP targets onto CONNECT-UDP streams of the shared
// H3 connection.
type packetConn struct {
	client *Client

	mu     sync.Mutex
	flows  map[string]*udpFlow // key: raddr String()
	closed bool

	readCh chan *datagram
	ctx    context.Context
	cancel context.CancelFunc
}

var _ net.PacketConn = (*packetConn)(nil)

func (pc *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	d, ok := <-pc.readCh
	if !ok {
		return 0, nil, errMasqueClosed
	}
	n := copy(p, d.payload)
	return n, d.raddr, nil
}

func (pc *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	raddr, ok := addr.(*net.UDPAddr)
	if !ok {
		udp, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return 0, fmt.Errorf("masque: target must be a UDP address, got %T", addr)
		}
		raddr = udp
	}
	if len(p) > maxDatagramSize {
		return 0, fmt.Errorf("masque: datagram exceeds %d bytes", maxDatagramSize)
	}
	flow, err := pc.flow(raddr)
	if err != nil {
		return 0, err
	}
	// RFC 9298 section 4: HTTP datagram payload = context id + UDP payload.
	buf := quicvarint.Append(nil, 0)
	buf = append(buf, p...)
	if err := flow.str.SendDatagram(buf); err != nil {
		pc.dropFlow(raddr.String())
		return 0, fmt.Errorf("masque: send datagram: %w", err)
	}
	return len(p), nil
}

// flow returns (and lazily establishes) the CONNECT-UDP stream for raddr.
func (pc *packetConn) flow(raddr *net.UDPAddr) (*udpFlow, error) {
	key := raddr.String()
	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		return nil, errMasqueClosed
	}
	if f, ok := pc.flows[key]; ok {
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
		flow.str.CancelWrite(0)
		return nil, errMasqueClosed
	}
	if existing, ok := pc.flows[key]; ok { // raced with a concurrent open
		pc.mu.Unlock()
		flow.str.CancelWrite(0)
		return existing, nil
	}
	pc.flows[key] = flow
	pc.mu.Unlock()

	go pc.flowReadLoop(flow)
	return flow, nil
}

// flowReadLoop pumps HTTP datagrams from one CONNECT-UDP stream.
func (pc *packetConn) flowReadLoop(flow *udpFlow) {
	for {
		buf, err := flow.str.ReceiveDatagram(pc.ctx)
		if err != nil {
			pc.dropFlow(flow.target.String())
			return
		}
		contextID, consumed, err := quicvarint.Parse(buf)
		if err != nil {
			pc.dropFlow(flow.target.String())
			return
		}
		if contextID != 0 {
			continue
		}
		payload := buf[consumed:]
		if len(payload) == 0 {
			continue
		}
		d := &datagram{payload: append([]byte(nil), payload...), raddr: flow.target}
		select {
		case pc.readCh <- d:
		case <-pc.ctx.Done():
			return
		}
	}
}

func (pc *packetConn) dropFlow(key string) {
	pc.mu.Lock()
	flow, ok := pc.flows[key]
	delete(pc.flows, key)
	pc.mu.Unlock()
	if ok {
		flow.str.CancelWrite(0)
	}
}

func (pc *packetConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (pc *packetConn) SetDeadline(t time.Time) error      { return nil }
func (pc *packetConn) SetReadDeadline(t time.Time) error  { return nil }
func (pc *packetConn) SetWriteDeadline(t time.Time) error { return nil }

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
	pc.flows = make(map[string]*udpFlow)
	pc.mu.Unlock()
	for _, f := range flows {
		f.str.CancelWrite(0)
	}
	pc.cancel()
	close(pc.readCh)
	return nil
}

var errMasqueClosed = errors.New("masque: packet conn closed")
