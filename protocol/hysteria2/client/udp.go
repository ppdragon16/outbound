package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	rand "github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pkg/oops"
	"github.com/daeuniverse/outbound/pool"

	"github.com/daeuniverse/quic-go"

	P "github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/frag"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

const (
	udpMessageChanSize = 128

	// defraggerTimeout is how long an incomplete reassembly may retain its
	// fragments before being abandoned. QUIC datagrams are unreliable, so a
	// lost fragment can never arrive; without a timeout the per-PacketID
	// Defragger (and the pooled buffers it holds) would leak until the
	// session closes.
	defraggerTimeout = 5 * time.Second

	// defraggerSweepInterval bounds how often ReadFromAddrPort scans for
	// abandoned reassemblies, keeping the hot path cheap.
	defraggerSweepInterval = defraggerTimeout
)

type udpConn struct {
	ID        uint32
	ReceiveCh chan []byte

	conn quic.Connection
	sm   *udpSessionManager

	ctx    context.Context
	cancel context.CancelFunc

	// deFraggers reassembles fragmented datagrams by PacketID. Guarded by
	// receiveMu (same as the old single Defragger's Feed/Close).
	deFraggers map[uint16]*frag.Defragger
	// lastSweep bounds how often ReadFromAddrPort scans deFraggers for
	// abandoned reassemblies. Guarded by receiveMu.
	lastSweep time.Time

	receiveMu    sync.Mutex
	readDeadline P.Deadline
}

func ToAddrPort(addr net.Addr) (netip.AddrPort, error) {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.AddrPort(), nil
	case *net.TCPAddr:
		return v.AddrPort(), nil
	default:
		return netip.ParseAddrPort(addr.String())
	}
}

func (u *udpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, ap, err := u.ReadFromAddrPort(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(ap), nil
}

func (u *udpConn) ReadFromAddrPort(p []byte) (n int, ap netip.AddrPort, err error) {
	var msg protocol.UDPMessage
	for {
		// Opportunistically abandon reassemblies whose fragments never
		// completed (a fragment was lost). Bounded to defraggerSweepInterval.
		u.receiveMu.Lock()
		if now := time.Now(); now.Sub(u.lastSweep) >= defraggerSweepInterval {
			u.lastSweep = now
			u.sweepDeFraggers(now)
		}
		u.receiveMu.Unlock()

		select {
		case <-u.ctx.Done():
			return 0, netip.AddrPort{}, io.ErrClosedPipe
		case <-u.readDeadline.Wait():
			return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
		case datagram, ok := <-u.ReceiveCh:
			if !ok {
				return 0, netip.AddrPort{}, io.EOF
			}
			if err := protocol.ParseUDPMessage(datagram, &msg); err != nil {
				pool.PutBuffer(datagram)
				continue
			}
			msg.DataBuf = datagram // set after Parse; it resets to nil
			if msg.FragCount <= 1 {
				// Single fragment: copy and release immediately.
				n = copy(p, msg.Data)
				pool.PutBuffer(datagram)
				return n, msg.AddrPort, nil
			}
			// Fragmented: reassemble by PacketID. Each PacketID gets its own
			// Defragger, so interleaved fragments of different packets do not
			// discard each other (unlike the old single-slot Defragger).
			u.receiveMu.Lock()
			n, ok = u.feedDefrag(&msg, p)
			u.receiveMu.Unlock()
			if !ok {
				continue
			}
			return n, msg.AddrPort, nil
		}
	}
}

// feedDefrag feeds a fragment to its per-PacketID Defragger, creating one on
// first use and abandoning (releasing) it once defraggerTimeout elapses without
// completion. Caller must hold receiveMu.
func (u *udpConn) feedDefrag(m *protocol.UDPMessage, p []byte) (int, bool) {
	now := time.Now()
	d := u.deFraggers[m.PacketID]
	if d == nil {
		if u.deFraggers == nil {
			u.deFraggers = make(map[uint16]*frag.Defragger, 2)
		}
		d = frag.GetDefragger(pool.PutBuffer)
		d.ExpiresAt = now.Add(defraggerTimeout)
		u.deFraggers[m.PacketID] = d
	} else if now.After(d.ExpiresAt) {
		// Previous reassembly was abandoned (a fragment was lost); replace
		// the stale Defragger, releasing its retained buffers.
		d.Put()
		d = frag.GetDefragger(pool.PutBuffer)
		d.ExpiresAt = now.Add(defraggerTimeout)
		u.deFraggers[m.PacketID] = d
	}
	n, assembled := d.Feed(m, p)
	if assembled {
		delete(u.deFraggers, m.PacketID)
		d.Put()
	}
	return n, assembled
}

// sweepDeFraggers releases and removes abandoned reassemblies. Caller must
// hold receiveMu.
func (u *udpConn) sweepDeFraggers(now time.Time) {
	for pktID, d := range u.deFraggers {
		if now.After(d.ExpiresAt) {
			d.Put()
			delete(u.deFraggers, pktID)
		}
	}
}

// releaseDeFraggers releases every in-flight reassembly. Called on Close so
// pooled buffers are returned even if the read loop is never resumed.
func (u *udpConn) releaseDeFraggers() {
	for pktID, d := range u.deFraggers {
		d.Put()
		delete(u.deFraggers, pktID)
	}
}

func (u *udpConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	ap, aErr := ToAddrPort(addr)
	if aErr != nil {
		return 0, aErr
	}
	return u.WriteToAddrPort(b, ap)
}

func (u *udpConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (n int, err error) {
	select {
	case <-u.ctx.Done():
		return 0, io.ErrClosedPipe
	default:
	}
	// Try no frag first. msg is a stack value: the whole serialize/fragment
	// chain takes UDPMessage by value (read-only), so it never escapes.
	msg := protocol.UDPMessage{
		SessionID: u.ID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		AddrPort:  ap,
		Data:      b,
	}
	buf := pool.GetBuffer(protocol.MaxUDPSize)
	defer pool.PutBuffer(buf)
	err = u.WritePacket(buf, msg)
	var errTooLarge *quic.DatagramTooLargeError
	if errors.As(err, &errTooLarge) {
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs := frag.FragUDPMessage(msg, int(errTooLarge.MaxDataLen))
		for _, fMsg := range fMsgs {
			err := u.WritePacket(buf, fMsg)
			if err != nil {
				return 0, oops.Wrapf(err, "failed to send fragment")
			}
		}
		return len(b), nil
	}
	return len(b), oops.Wrapf(err, "failed to SendDatagram")
}

func (u *udpConn) WritePacket(buf []byte, msg protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		return &quic.DatagramTooLargeError{MaxDataLen: int64(len(buf))}
	}
	err := u.conn.SendDatagram(buf[:msgN])
	if errors.Is(err, quic.ErrDatagramQueueFullTimeout) {
		// The datagram send queue stayed full with nothing dequeued for the
		// timeout: the transport is stalled, not merely backpressured. Retire
		// the whole connection so this and every other in-flight write fails
		// fast (closeErr) instead of blocking another timeout each, and so
		// Client.Alive() turns false and dae re-dials promptly.
		_ = u.conn.CloseWithError(closeErrCodeProtocolError, "datagram send queue full: timed out")
	}
	return err
}

func (u *udpConn) Close() error {
	u.cancel()
	u.sm.connMap.Delete(u.ID)
	u.receiveMu.Lock()
	u.releaseDeFraggers()
	u.receiveMu.Unlock()
	// Drain datagrams still queued for this session and return their pooled
	// buffers. connMap.Delete happened above, so no new feed() can target this
	// session; anything left in ReceiveCh will never be read again and would
	// otherwise leak its pool buffer (up to udpMessageChanSize per session).
	for {
		select {
		case buf := <-u.ReceiveCh:
			pool.PutBuffer(buf)
		default:
			return nil
		}
	}
}

func (u *udpConn) SetDeadline(t time.Time) error {
	return oops.Join(u.SetReadDeadline(t), u.SetWriteDeadline(t))
}

func (u *udpConn) SetReadDeadline(t time.Time) error {
	u.readDeadline.Set(t)
	return nil
}

// QUIC raw datagram can block on a full send queue, but only up to
// quic-go's datagramSendQueueFullTimeout; after that it returns
// ErrDatagramQueueFullTimeout and WritePacket retires the connection.
func (u *udpConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (u *udpConn) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}

type udpSessionManager struct {
	conn quic.Connection

	connMap sync.Map // map[uint32]*udpConn
	nextID  uint32

	ctx    context.Context
	cancel context.CancelFunc
}

func newUDPSessionManager(conn quic.Connection) *udpSessionManager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &udpSessionManager{
		conn:   conn,
		nextID: 1,
		ctx:    ctx,
		cancel: cancel,
	}
	// Single receive goroutine on purpose. The per-session Defragger is
	// single-slot (one PacketID at a time) and assumes fragments arrive in
	// wire order: a parallel demux reorders datagram delivery, which (a) makes
	// fragments of different packets interleave and get discarded, and (b)
	// reorders non-fragmented datagrams beyond QUIC's kPacketThreshold (3),
	// triggering spurious loss at the inner QUIC sender. Do not parallelize
	// this loop without first making the Defragger reassemble by PacketID.
	go m.run()
	return m
}

func (m *udpSessionManager) run() error {
	for {
		datagram, err := m.conn.ReceiveDatagram(m.ctx)
		if err != nil {
			m.Close()
			return err
		}
		m.feed(datagram)
	}
}

func (m *udpSessionManager) Close() {
	m.cancel()
}

func (m *udpSessionManager) IsClosed() bool {
	return m.ctx.Err() != nil
}

func (m *udpSessionManager) feed(datagram []byte) {
	if len(datagram) < 9 {
		// Invalid message, this is fine - just wait for the next.
		// Release the pooled buffer now: nobody will consume it.
		m.conn.ReleaseDatagram(datagram)
		return
	}
	conn, ok := m.connMap.Load(binary.BigEndian.Uint32(datagram))
	if !ok {
		// Ignore message from unknown session
		m.conn.ReleaseDatagram(datagram)
		return
	}

	// Copy into a pool buffer so the quic-go buffer can be released
	// immediately — avoids exhausting the bounded datagramBufPool.
	buf := pool.GetBuffer(len(datagram))
	copy(buf, datagram)
	m.conn.ReleaseDatagram(datagram)

	select {
	case conn.(*udpConn).ReceiveCh <- buf:
		// OK
	default:
		// Channel full, drop the message.
		pool.PutBuffer(buf)
	}
}

// NewUDP creates a new UDP session.
func (m *udpSessionManager) NewUDP() (net.PacketConn, error) {
	id := m.nextID
	m.nextID++

	ctx, cancel := context.WithCancel(m.ctx)
	conn := &udpConn{
		ID:           id,
		ReceiveCh:    make(chan []byte, udpMessageChanSize),
		conn:         m.conn,
		sm:           m,
		ctx:          ctx,
		cancel:       cancel,
		readDeadline: P.MakeDeadline(),
	}
	m.connMap.Store(id, conn)

	return conn, nil
}
