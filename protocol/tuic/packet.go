package tuic

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

const packetChanCap = 2048

type Packets struct {
	mu     sync.Mutex
	ch     chan *Packet
	closed atomic.Bool
}

func NewPackets() *Packets {
	return &Packets{
		ch: make(chan *Packet, packetChanCap),
	}
}

func (p *Packets) PushBack(packet *Packet) {
	p.mu.Lock()
	if p.closed.Load() {
		p.mu.Unlock()
		packet.releaseData()
		return
	}
	// Channel send while holding mu so concurrent Close cannot close the
	// channel underneath us (Close also acquires mu before close).
	p.ch <- packet
	p.mu.Unlock()
}

func (p *Packets) PopFrontBlock() (packet *Packet, closed bool) {
	packet, ok := <-p.ch
	if !ok {
		return nil, true
	}
	return packet, false
}

func (p *Packets) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return nil
	}
	p.closed.Store(true)
	// Drain buffered packets so pool-backed DATA is returned.
	// No new PushBack can run concurrently — it would block on p.mu.
	for len(p.ch) > 0 {
		if pkt := <-p.ch; pkt != nil {
			pkt.releaseData()
		}
	}
	close(p.ch)
	return nil
}

type quicStreamPacketConn struct {
	mu sync.Mutex

	target string

	connId          uint16
	quicConn        quic.Connection
	incomingPackets *Packets

	udpRelayMode          common.UdpRelayMode
	maxUdpRelayPacketSize int

	deferQuicConnFn func(quicConn quic.Connection, err error)
	closeDeferFn    func()

	closeOnce sync.Once
	closeErr  error
	closed    bool

	// TODO: multiple defraggers for different PKT_ID
	deFraggers sync.Map

	muTimer       sync.Mutex
	deadlineTimer *time.Timer
}

func (q *quicStreamPacketConn) Close() error {
	q.closeOnce.Do(func() {
		q.closed = true
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (q *quicStreamPacketConn) close() (err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closeDeferFn != nil {
		defer q.closeDeferFn()
	}
	if q.deferQuicConnFn != nil {
		defer func() {
			q.deferQuicConnFn(q.quicConn, err)
		}()
	}
	if q.incomingPackets != nil {
		// Close the queue BEFORE the Dissociate so blocked PopFrontBlock
		// callers unblock immediately instead of leaking.
		pkts := q.incomingPackets
		q.incomingPackets = nil
		pkts.Close()

		// Best-effort: tell the server to release this UDP association.
		// If it fails (stream limit, dead conn, etc.), the server
		// will eventually timeout the association on its own.
		buf := pool.GetBytesBuffer()
		defer pool.PutBytesBuffer(buf)
		if e := NewDissociate(q.connId, Ver5).WriteTo(buf); e != nil {
			return // non-fatal: we already closed the queue
		}
		stream, e := q.quicConn.OpenUniStream()
		if e != nil {
			return // non-fatal
		}
		if _, e = buf.WriteTo(stream); e != nil {
			return // non-fatal
		}
		_ = stream.Close()
	}
	return
}

func (q *quicStreamPacketConn) SetDeadline(t time.Time) error {
	q.muTimer.Lock()
	defer q.muTimer.Unlock()
	dur := time.Until(t)
	if q.deadlineTimer != nil {
		q.deadlineTimer.Reset(dur)
	} else {
		q.deadlineTimer = time.AfterFunc(dur, func() {
			q.muTimer.Lock()
			defer q.muTimer.Unlock()
			q.Close()
			q.deadlineTimer = nil
		})
	}
	return nil
}

func (q *quicStreamPacketConn) SetReadDeadline(t time.Time) error {
	// FIXME: Single direction.
	return q.SetDeadline(t)
}

func (q *quicStreamPacketConn) SetWriteDeadline(t time.Time) error {
	// FIXME: Single direction.
	return q.SetDeadline(t)
}

// ToAddrPort converts a net.Addr to netip.AddrPort, preferring the AddrPort()
// method (zero-allocation for net.UDPAddr), falling back to parsing the string form.
func ToAddrPort(addr net.Addr) (netip.AddrPort, error) {
	if addr, ok := addr.(interface{ AddrPort() netip.AddrPort }); ok {
		if ap := addr.AddrPort(); ap.IsValid() {
			return ap, nil
		}
	}
	addrStr := addr.String()
	return netip.ParseAddrPort(addrStr)
}

// ReadFrom implements net.PacketConn. Thin wrapper around ReadFromAddrPort.
func (q *quicStreamPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, ap, err := q.ReadFromAddrPort(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(ap), nil
}

// WriteTo implements net.PacketConn. Thin wrapper around WriteToAddrPort.
func (q *quicStreamPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ap, err := ToAddrPort(addr)
	if err != nil {
		return 0, err
	}
	return q.WriteToAddrPort(p, ap)
}

// ReadFromAddrPort reads a packet and returns the source as netip.AddrPort.
func (q *quicStreamPacketConn) ReadFromAddrPort(p []byte) (n int, ap netip.AddrPort, err error) {
	q.mu.Lock()
	incomingPackets := q.incomingPackets
	q.mu.Unlock()
	if incomingPackets != nil {
		for {
			packet, closed := incomingPackets.PopFrontBlock()
			if closed {
				err = net.ErrClosed
				return
			}
			if packet.FRAG_TOTAL <= 1 {
			n = copy(p, packet.DATA)
			if packet.ADDR != nil {
				ap = packet.ADDR.UDPAddr().AddrPort()
			}
			packet.releaseData()
			return
		}
		_d, _ := q.deFraggers.LoadOrStore(packet.PKT_ID, &deFragger{})
			d := _d.(*deFragger)
			var assembled bool
			if n, ap, assembled = d.Feed(packet, p); assembled {
				q.deFraggers.Delete(packet.PKT_ID)
				return
			}
			// FIXME: Timeout to clean deFraggers.
		}
	} else {
		err = net.ErrClosed
	}
	return
}

// WriteToAddrPort writes a packet to the given netip.AddrPort.
func (q *quicStreamPacketConn) WriteToAddrPort(p []byte, ap netip.AddrPort) (n int, err error) {
	if len(p) > 0xffff { // uint16 max
		return 0, &quic.DatagramTooLargeError{MaxDataLen: 0xffff}
	}
	if q.closed {
		return 0, net.ErrClosed
	}
	if q.deferQuicConnFn != nil {
		defer func() {
			q.deferQuicConnFn(q.quicConn, err)
		}()
	}
	pktId := uint16(fastrand.Uint32())
	switch q.udpRelayMode {
	case common.QUIC:
		buf := buildPacketBuf(q.connId, pktId, 1, 0, p, ap)
		defer pool.PutBuffer(buf)
		stream, err := q.quicConn.OpenUniStream()
		if err != nil {
			return 0, err
		}
		defer stream.Close()
		_, err = stream.Write(buf)
		if err != nil {
			return 0, err
		}
	default: // native
		if len(p) > q.maxUdpRelayPacketSize {
			err = fragWriteNative(q.quicConn, q.connId, pktId, ap, p, q.maxUdpRelayPacketSize)
			if err != nil {
				return 0, err
			}
		} else {
			buf := buildPacketBuf(q.connId, pktId, 1, 0, p, ap)
			err = q.quicConn.SendDatagram(buf)
			pool.PutBuffer(buf)
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				err = fragWriteNative(q.quicConn, q.connId, pktId, ap, p, int(tooLarge.MaxDataLen)-PacketOverHead)
			}
			if err != nil {
				return 0, err
			}
		}
	}
	n = len(p)

	return
}

func (q *quicStreamPacketConn) LocalAddr() net.Addr {
	return q.quicConn.LocalAddr()
}

func (conn *quicStreamPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = conn.ReadFromAddrPort(b)
	return n, err
}

func (conn *quicStreamPacketConn) Write(b []byte) (n int, err error) {
	ap, err := netip.ParseAddrPort(conn.target)
	if err != nil {
		return 0, err
	}
	return conn.WriteToAddrPort(b, ap)
}

var _ net.PacketConn = (*quicStreamPacketConn)(nil)
