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

	ctx    context.Context
	cancel context.CancelFunc

	closeCallback func()

	readDeadline P.Deadline
}

func (u *udpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		select {
		case <-u.ctx.Done():
			return 0, nil, io.ErrClosedPipe
		case <-u.readDeadline.Wait():
			return 0, nil, os.ErrDeadlineExceeded
		case msg, ok := <-u.ReceiveCh:
			if !ok {
				return 0, nil, io.EOF
			}
			dfMsg := u.D.Feed(msg)
			if dfMsg == nil {
				// Incomplete message, wait for more
				continue
			}
			// TODO: 避免copy
			return copy(p, dfMsg.Data), net.UDPAddrFromAddrPort(netip.MustParseAddrPort(dfMsg.Addr)), nil
		}
	}
}

func (u *udpConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
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
		Addr:      addr.String(),
		Data:      b,
	}
	buf := pool.Get(protocol.MaxUDPSize)
	defer buf.Put()
	err = u.WritePacket(buf, msg)
	var errTooLarge *quic.DatagramTooLargeError
	if errors.As(err, &errTooLarge) {
		// Message too large, try fragmentation
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs := frag.FragUDPMessage(msg, int(errTooLarge.MaxDataLen))
		for _, fMsg := range fMsgs {
			err := u.WritePacket(buf, &fMsg)
			if err != nil {
				return 0, err
			}
		}
		return len(b), nil
	} else {
		return len(b), err
	}
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
	u.closeCallback()
	return nil
}

func (u *udpConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (u *udpConn) SetReadDeadline(t time.Time) error {
	u.readDeadline.Set(t)
	return nil
}

// QUIC does not support write deadline for raw datagram.
func (u *udpConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
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
	if m.ctx.Err() != nil {
		return nil, oops.In("New udpSM").New("UDP session manager closed")
	}

	id := m.nextID
	m.nextID++

	ctx, cancel := context.WithCancel(m.ctx)
	conn := &udpConn{
		ID:           id,
		D:            &frag.Defragger{},
		ReceiveCh:    make(chan *protocol.UDPMessage, udpMessageChanSize),
		conn:         m.conn,
		ctx:          ctx,
		cancel:       cancel,
		readDeadline: P.MakeDeadline(),
	}
	conn.closeCallback = func() {
		m.connMap.Delete(conn.ID)
	}
	m.connMap.Store(id, conn)

	return conn, nil
}
