package client

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	rand "github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/samber/oops"

	"github.com/daeuniverse/quic-go"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/frag"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

const (
	udpMessageChanSize = 1024
)

type udpIO interface {
	ReceiveMessage(context.Context) (*protocol.UDPMessage, error)
	SendMessage([]byte, *protocol.UDPMessage) error
}

type udpConn struct {
	ID        uint32
	D         *frag.Defragger
	ReceiveCh chan *protocol.UDPMessage
	SendBuf   []byte
	SendFunc  func([]byte, *protocol.UDPMessage) error
	CloseFunc func()
	Closed    bool

	muTimer sync.Mutex
	timer   *time.Timer
	target  string
}

func (u *udpConn) Read(b []byte) (n int, err error) {
	msg, _, err := u.ReadFrom(b)
	return msg, err
}

func (u *udpConn) Write(b []byte) (n int, err error) {
	return u.WriteTo(b, u.target)
}

func (u *udpConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	for {
		msg := <-u.ReceiveCh
		if msg == nil {
			// Closed
			return 0, netip.AddrPort{}, io.EOF
		}
		dfMsg := u.D.Feed(msg)
		if dfMsg == nil {
			// Incomplete message, wait for more
			continue
		}
		netipAddr, err := netip.ParseAddrPort(dfMsg.Addr)
		if err != nil {
			return 0, netipAddr, err
		}
		return copy(p, dfMsg.Data), netipAddr, nil
	}
}

func (u *udpConn) WriteTo(b []byte, addr string) (n int, err error) {
	// Try no frag first
	msg := &protocol.UDPMessage{
		SessionID: u.ID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      addr,
		Data:      b,
	}
	err = u.SendFunc(u.SendBuf, msg)
	var errTooLarge *quic.DatagramTooLargeError
	if errors.As(err, &errTooLarge) {
		// Message too large, try fragmentation
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs := frag.FragUDPMessage(msg, int(errTooLarge.MaxDataLen))
		for _, fMsg := range fMsgs {
			err := u.SendFunc(u.SendBuf, &fMsg)
			if err != nil {
				return 0, err
			}
		}
		return len(b), nil
	} else {
		return len(b), err
	}
}

func (u *udpConn) Close() error {
	u.CloseFunc()
	return nil
}

func (u *udpConn) SetDeadline(t time.Time) error {
	u.muTimer.Lock()
	defer u.muTimer.Unlock()
	dur := time.Until(t)
	if u.timer != nil {
		u.timer.Reset(dur)
	} else {
		u.timer = time.AfterFunc(dur, func() {
			u.muTimer.Lock()
			defer u.muTimer.Unlock()
			u.Close()
			u.timer = nil
		})
	}
	return nil
}

func (u *udpConn) SetReadDeadline(t time.Time) error {
	// FIXME: Single direction.
	return u.SetDeadline(t)
}

func (u *udpConn) SetWriteDeadline(t time.Time) error {
	// FIXME: Single direction.
	return u.SetDeadline(t)
}

type udpSessionManager struct {
	io udpIO

	mutex  sync.RWMutex
	m      map[uint32]*udpConn
	nextID uint32

	ctx    context.Context
	cancel context.CancelFunc
}

func newUDPSessionManager(io udpIO) *udpSessionManager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &udpSessionManager{
		io:     io,
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		ctx:    ctx,
		cancel: cancel,
	}
	go m.run()
	return m
}

func (m *udpSessionManager) run() error {
	for {
		msg, err := m.io.ReceiveMessage(m.ctx)
		if err != nil {
			m.Close()
			return oops.In("UDP session manager").With("ctx", m.ctx).Wrapf(err, "failed to receive message")
		}
		m.feed(msg)
	}
}

func (m *udpSessionManager) Close() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, conn := range m.m {
		m.close(conn)
	}
	m.cancel()
}

func (m *udpSessionManager) feed(msg *protocol.UDPMessage) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	conn, ok := m.m[msg.SessionID]
	if !ok {
		// Ignore message from unknown session
		return
	}

	select {
	case conn.ReceiveCh <- msg:
		// OK
	default:
		// Channel full, drop the message
	}
}

// NewUDP creates a new UDP session.
func (m *udpSessionManager) NewUDP(addr string) (netproxy.Conn, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.ctx.Err() != nil {
		return nil, oops.In("New udpSM").New("UDP session manager closed")
	}

	id := m.nextID
	m.nextID++

	conn := &udpConn{
		ID:        id,
		D:         &frag.Defragger{},
		ReceiveCh: make(chan *protocol.UDPMessage, udpMessageChanSize),
		SendBuf:   make([]byte, protocol.MaxUDPSize),
		SendFunc:  m.io.SendMessage,

		muTimer: sync.Mutex{},
		target:  addr,
	}
	conn.CloseFunc = func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.close(conn)
	}
	m.m[id] = conn

	return conn, nil
}

func (m *udpSessionManager) close(conn *udpConn) {
	if !conn.Closed {
		conn.Closed = true
		close(conn.ReceiveCh)
		delete(m.m, conn.ID)
	}
}

func (m *udpSessionManager) Count() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.m)
}
