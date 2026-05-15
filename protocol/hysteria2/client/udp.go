package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	rand "github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/samber/oops"

	"github.com/daeuniverse/quic-go"

	P "github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/frag"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

const (
	udpMessageChanSize = 1024
)

type udpConn struct {
	ID        uint32
	D         *frag.Defragger
	ReceiveCh chan *protocol.UDPMessage

	conn quic.Connection
	sm   *udpSessionManager

	ctx    context.Context
	cancel context.CancelFunc

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
	for {
		select {
		case <-u.ctx.Done():
			return 0, netip.AddrPort{}, io.ErrClosedPipe
		case <-u.readDeadline.Wait():
			return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
		case msg, ok := <-u.ReceiveCh:
			if !ok {
				return 0, netip.AddrPort{}, io.EOF
			}
			dfMsg := u.D.Feed(msg)
			if dfMsg == nil {
				// Incomplete message, wait for more
				continue
			}
			ap, err := netip.ParseAddrPort(dfMsg.Addr)
			if err != nil {
				return 0, netip.AddrPort{}, err
			}
			// TODO: 避免copy
			return copy(p, dfMsg.Data), ap, nil
		}
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
	// Try no frag first
	msg := &protocol.UDPMessage{
		SessionID: u.ID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      ap.String(),
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
			err := u.WritePacket(buf, &fMsg)
			if err != nil {
				return 0, err
			}
		}
		return len(b), nil
	}
	return len(b), err
}

func (u *udpConn) WritePacket(buf []byte, msg *protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		// Message larger than buffer, silent drop
		return nil
	}
	err := u.conn.SendDatagram(buf[:msgN])
	return oops.Wrapf(err, "failed to SendDatagram")
}

func (u *udpConn) Close() error {
	u.cancel()
	u.sm.connMap.Delete(u.ID)
	return nil
}

func (u *udpConn) SetDeadline(t time.Time) error {
	return oops.Join(u.SetReadDeadline(t), u.SetWriteDeadline(t))
}

func (u *udpConn) SetReadDeadline(t time.Time) error {
	u.readDeadline.Set(t)
	return nil
}

// QUIC raw datagram will not block on write.
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
		msg, err := protocol.ParseUDPMessage(datagram)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		m.feed(msg)
	}
}

func (m *udpSessionManager) Close() {
	m.cancel()
}

func (m *udpSessionManager) IsClosed() bool {
	return m.ctx.Err() != nil
}

func (m *udpSessionManager) feed(msg *protocol.UDPMessage) {
	conn, ok := m.connMap.Load(msg.SessionID)
	if !ok {
		// Ignore message from unknown session
		return
	}

	select {
	case conn.(*udpConn).ReceiveCh <- msg:
		// OK
	default:
		// Channel full, drop the message
	}
}

// NewUDP creates a new UDP session.
func (m *udpSessionManager) NewUDP() (net.PacketConn, error) {
	id := m.nextID
	m.nextID++

	ctx, cancel := context.WithCancel(m.ctx)
	conn := &udpConn{
		ID:           id,
		D:            &frag.Defragger{},
		ReceiveCh:    make(chan *protocol.UDPMessage, udpMessageChanSize),
		conn:         m.conn,
		sm:           m,
		ctx:          ctx,
		cancel:       cancel,
		readDeadline: P.MakeDeadline(),
	}
	m.connMap.Store(id, conn)

	return conn, nil
}
