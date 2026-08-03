package tuic

import (
	"container/list"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

type Packets struct {
	mu               sync.Mutex
	list             *list.List
	isEmptyState     context.Context
	cancelEmptyState func()
	closed           bool
}

func NewPackets() *Packets {
	ctx, cancel := context.WithCancel(context.Background())
	return &Packets{
		mu:               sync.Mutex{},
		list:             list.New().Init(),
		isEmptyState:     ctx,
		cancelEmptyState: cancel,
	}
}

func (p *Packets) PushBack(packet *Packet) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		packet.releaseData()
		return
	}
	p.list.PushBack(packet)
	select {
	case <-p.isEmptyState.Done():
	default:
		p.cancelEmptyState()
	}
}

func (p *Packets) PopFrontBlock() (packet *Packet, closed bool) {
	<-p.isEmptyState.Done()
	if p.closed {
		return nil, true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	packet = p.list.Remove(p.list.Front()).(*Packet)
	if p.list.Len() == 0 {
		p.setEmpty()
	}
	return packet, false
}

func (p *Packets) setEmpty() {
	p.isEmptyState, p.cancelEmptyState = context.WithCancel(context.Background())
}

func (p *Packets) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	select {
	case <-p.isEmptyState.Done():
	default:
		p.cancelEmptyState()
	}
	for p.list.Len() > 0 {
		pkt := p.list.Remove(p.list.Front()).(*Packet)
		pkt.releaseData()
	}
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
		q.incomingPackets = nil

		buf := pool.GetBytesBuffer()
		defer pool.PutBytesBuffer(buf)
		err = NewDissociate(q.connId, Ver5).WriteTo(buf)
		if err != nil {
			return
		}
		var stream quic.SendStream
		stream, err = q.quicConn.OpenUniStream()
		if err != nil {
			return
		}
		_, err = buf.WriteTo(stream)
		if err != nil {
			return
		}
		err = stream.Close()
		if err != nil {
			return
		}
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
