package udphop

import (
	"context"
	"errors"
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

	// addr is the source of port range and IP. Random ports are picked
	// on demand via addr.PickRandomAddr() rather than pre-expanding into
	// a slice — that would be ~11 KiB for "60000-65530".
	addr *UDPHopAddr

	dialFunc dialFunc

	connMutex   sync.RWMutex
	prevConn    net.Conn
	currentConn net.Conn

	// fixedAddr, when non-nil, pins the connection to a specific remote
	// port and disables the periodic hop loop. Used by Client to
	// implement port memory: once a port is known to work, subsequent
	// connections stick to it (and stop hopping) until that port stops
	// working.
	fixedAddr *net.UDPAddr

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

// NewUDPHopPacketConn creates a new UDP hop packet connection.
//
// If fixedAddr is non-nil, the initial dial uses that address and the
// periodic hop loop is disabled — the connection stays on this port
// for its lifetime. This is used to implement port memory: once a
// port in the hop range is known to work, the Client pins the
// connection to it so the random hop loop cannot later pick a port
// the server is not listening on.
//
// If fixedAddr is nil, the initial dial is random (from addr.Ranges)
// and the hop loop runs as usual.
func NewUDPHopPacketConn(addr *UDPHopAddr, hopInterval time.Duration, dialFunc dialFunc, fixedAddr *net.UDPAddr) (net.PacketConn, error) {
	if hopInterval == 0 {
		hopInterval = defaultHopInterval
	} else if hopInterval < 5*time.Second {
		return nil, errors.New("hop interval must be at least 5 seconds")
	}
	if addr.TotalPorts() == 0 {
		return nil, InvalidPortError{addr.PortStr}
	}

	initial := fixedAddr
	if initial == nil {
		initial = addr.PickRandomAddr()
	}
	curConn, err := dialFunc(initial)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	hConn := &udpHopPacketConn{
		HopInterval: hopInterval,
		addr:        addr,
		dialFunc:    dialFunc,
		currentConn: curConn,
		fixedAddr:   fixedAddr,
		recvQueue:   make(chan *udpPacket, packetQueueSize),
		ctx:         ctx,
		cancel:      cancel,
	}
	go hConn.recvLoop(curConn)
	if fixedAddr == nil {
		go hConn.hopLoop()
	}
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
	// If the connection is pinned to a fixed port, hopping is a no-op:
	// the hop loop is not started in this case, but guard here too in
	// case fixedAddr is set after construction.
	if u.fixedAddr != nil {
		return
	}
	newConn, err := u.dialFunc(u.addr.PickRandomAddr())
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

// RemotePort returns the remote port of the underlying current
// connection. Used by Client to remember which port in the hop range
// last succeeded, so subsequent connections can pin to it instead of
// re-rolling random ports.
//
// Returns 0 if the remote address is not a *net.UDPAddr (e.g. when
// the connection is being torn down).
func (u *udpHopPacketConn) RemotePort() int {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.currentConn == nil {
		return 0
	}
	if addr, ok := u.currentConn.RemoteAddr().(*net.UDPAddr); ok {
		return addr.Port
	}
	return 0
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
