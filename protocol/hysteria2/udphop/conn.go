package udphop

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/samber/oops"
)

const (
	packetQueueSize = 1024
	udpBufferSize   = 2048 // QUIC packets are at most 1500 bytes long, so 2k should be more than enough

	defaultHopInterval = 30 * time.Second
)

type udpHopPacketConn struct {
	HopInterval time.Duration

	addrs []net.Addr

	dialFunc dialFunc

	connMutex   sync.RWMutex
	prevConn    net.Conn
	currentConn net.Conn

	readBufferSize  int
	writeBufferSize int

	recvQueue chan *udpPacket

	ctx    context.Context
	cancel context.CancelFunc
}

type udpPacket struct {
	Buf  []byte
	N    int
	Addr net.Addr
	Err  error
}

type dialFunc = func(addr net.Addr) (net.Conn, error)

func NewUDPHopPacketConn(addr *UDPHopAddr, hopInterval time.Duration, dialFunc dialFunc) (net.PacketConn, error) {
	if hopInterval == 0 {
		hopInterval = defaultHopInterval
	} else if hopInterval < 5*time.Second {
		return nil, errors.New("hop interval must be at least 5 seconds")
	}
	addrs, err := addr.addrs()
	if err != nil {
		return nil, err
	}

	newAddrIndex := rand.Intn(len(addrs))
	curConn, err := dialFunc(addrs[newAddrIndex])
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	hConn := &udpHopPacketConn{
		HopInterval: hopInterval,
		addrs:       addrs,
		dialFunc:    dialFunc,
		currentConn: curConn,
		recvQueue:   make(chan *udpPacket, packetQueueSize),
		ctx:         ctx,
		cancel:      cancel,
	}
	go hConn.recvLoop(curConn)
	go hConn.hopLoop()
	return hConn, nil
}

func (u *udpHopPacketConn) recvLoop(conn net.Conn) {
	for {
		buf := pool.GetBuffer(udpBufferSize)
		n, err := conn.Read(buf)
		if err != nil {
			pool.PutBuffer(buf)
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Only pass through timeout errors here, not permanent errors
				// like connection closed. Connection close is normal as we close
				// the old connection to exit this loop every time we hop.
				u.recvQueue <- &udpPacket{nil, 0, nil, netErr}
			}
			return
		}
		select {
		case u.recvQueue <- &udpPacket{buf, n, conn.RemoteAddr(), nil}:
			// Packet successfully queued
		default:
			// Queue is full, drop the packet
			pool.PutBuffer(buf)
		}
	}
}

func (u *udpHopPacketConn) hopLoop() {
	ticker := time.NewTicker(u.HopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-ticker.C:
			u.hop()
		}
	}
}

func (u *udpHopPacketConn) hop() {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	newAddrIndex := rand.Intn(len(u.addrs))
	newConn, err := u.dialFunc(u.addrs[newAddrIndex])
	if err != nil {
		// Could be temporary, just skip this hop
		return
	}
	// We need to keep receiving packets from the previous connection,
	// because otherwise there will be packet loss due to the time gap
	// between we hop to a new port and the server acknowledges this change.
	// So we do the following:
	// Close prevConn,
	// move currentConn to prevConn,
	// set newConn as currentConn,
	// start recvLoop on newConn.
	if u.prevConn != nil {
		u.prevConn.Close() // recvLoop for this conn will exit
	}
	u.prevConn = u.currentConn
	u.currentConn = newConn
	// Set buffer sizes if previously set
	if u.readBufferSize > 0 {
		_ = trySetReadBuffer(u.currentConn, u.readBufferSize)
	}
	if u.writeBufferSize > 0 {
		_ = trySetWriteBuffer(u.currentConn, u.writeBufferSize)
	}
	go u.recvLoop(newConn)
}

func (u *udpHopPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case <-u.ctx.Done():
		return 0, nil, net.ErrClosed
	case p := <-u.recvQueue:
		if p.Err != nil {
			return 0, nil, p.Err
		}
		// Currently we do not check whether the packet is from
		// the server or not due to performance reasons.
		n := copy(b, p.Buf[:p.N])
		pool.PutBuffer(p.Buf)
		return n, p.Addr, nil
	}
}

func (u *udpHopPacketConn) WriteTo(b []byte, _ net.Addr) (n int, err error) {
	if u.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	// Skip the check for now, always write to the server,
	// for the same reason as in ReadFrom.
	return u.currentConn.Write(b)
}

func (u *udpHopPacketConn) Close() error {
	u.cancel()
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	// Close prevConn and currentConn
	// Close closeChan to unblock ReadFrom & hopLoop
	// Set closed flag to true to prevent double close
	err := u.currentConn.Close()
	if u.prevConn != nil {
		err = oops.Join(err, u.prevConn.Close())
	}
	return err
}

func (u *udpHopPacketConn) LocalAddr() net.Addr {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	return u.currentConn.LocalAddr()
}

func (u *udpHopPacketConn) SetDeadline(t time.Time) error {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.prevConn != nil {
		_ = u.prevConn.SetDeadline(t)
	}
	return u.currentConn.SetDeadline(t)
}

func (u *udpHopPacketConn) SetReadDeadline(t time.Time) error {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.prevConn != nil {
		_ = u.prevConn.SetReadDeadline(t)
	}
	return u.currentConn.SetReadDeadline(t)
}

func (u *udpHopPacketConn) SetWriteDeadline(t time.Time) error {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.prevConn != nil {
		_ = u.prevConn.SetWriteDeadline(t)
	}
	return u.currentConn.SetWriteDeadline(t)
}

// UDP-specific methods below

func (u *udpHopPacketConn) SetReadBuffer(bytes int) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.readBufferSize = bytes
	if u.prevConn != nil {
		_ = trySetReadBuffer(u.prevConn, bytes)
	}
	return trySetReadBuffer(u.currentConn, bytes)
}

func (u *udpHopPacketConn) SetWriteBuffer(bytes int) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.writeBufferSize = bytes
	if u.prevConn != nil {
		_ = trySetWriteBuffer(u.prevConn, bytes)
	}
	return trySetWriteBuffer(u.currentConn, bytes)
}

func (u *udpHopPacketConn) SyscallConn() (syscall.RawConn, error) {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	sc, ok := u.currentConn.(syscall.Conn)
	if !ok {
		return nil, errors.New("not supported")
	}
	return sc.SyscallConn()
}

func trySetReadBuffer(pc net.Conn, bytes int) error {
	sc, ok := pc.(interface {
		SetReadBuffer(bytes int) error
	})
	if ok {
		return sc.SetReadBuffer(bytes)
	}
	return nil
}

func trySetWriteBuffer(pc net.Conn, bytes int) error {
	sc, ok := pc.(interface {
		SetWriteBuffer(bytes int) error
	})
	if ok {
		return sc.SetWriteBuffer(bytes)
	}
	return nil
}
