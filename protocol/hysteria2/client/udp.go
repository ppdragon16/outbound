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
	"github.com/daeuniverse/outbound/pool"
	"github.com/samber/oops"

	"github.com/daeuniverse/quic-go"

	P "github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/frag"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

const (
	udpMessageChanSize = 128
)

type udpConn struct {
	ID        uint32
	D         *frag.Defragger
	ReceiveCh chan []byte

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
	var msg protocol.UDPMessage
	for {
		select {
		case <-u.ctx.Done():
			return 0, netip.AddrPort{}, io.ErrClosedPipe
		case <-u.readDeadline.Wait():
			return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
		case datagram, ok := <-u.ReceiveCh:
			if !ok {
				return 0, netip.AddrPort{}, io.EOF
			}
			msg.DataBuf = datagram
			if err := protocol.ParseUDPMessage(datagram, &msg); err != nil {
				u.conn.ReleaseDatagram(datagram)
				continue
			}
			if msg.FragCount <= 1 {
				// Single fragment: copy and release immediately.
				n = copy(p, msg.Data)
				u.conn.ReleaseDatagram(datagram)
				return n, msg.AddrPort, nil
			}
			// Fragmented: Defragger takes ownership of DataBuf;
			// it will release via ReleaseFn when assembly completes.
			n, ok = u.D.Feed(&msg, p)
			if !ok {
				continue
			}
			return n, msg.AddrPort, nil
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
	u.D.Close()
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

	select {
	case conn.(*udpConn).ReceiveCh <- datagram:
		// OK
	default:
		// Channel full, drop the message. Return the pooled datagram buffer
		// to quic-go now: nobody will ever consume it.
		m.conn.ReleaseDatagram(datagram)
	}
}

// NewUDP creates a new UDP session.
func (m *udpSessionManager) NewUDP() (net.PacketConn, error) {
	id := m.nextID
	m.nextID++

	ctx, cancel := context.WithCancel(m.ctx)
	conn := &udpConn{
		ID:           id,
		D:            &frag.Defragger{ReleaseFn: m.conn.ReleaseDatagram},
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
