package udphop

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/pkg/logger"
	"github.com/daeuniverse/outbound/pkg/oops"
	"github.com/daeuniverse/outbound/pool"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
)

const (
	// packetQueueSize only has to absorb scheduling jitter between the
	// recvLoop producer(s) and the QUIC transport reader — microseconds of
	// work per packet on both sides. 256 slots ≈ 2.5 ms of tolerance at
	// 100 kpps (Gbit line rate), well past any QUIC cwnd-sized burst, and
	// keeps the eager per-conn reservation at 24 KB instead of 96 KB.
	// Overflow is a non-blocking drop; QUIC recovers from loss on its own.
	packetQueueSize = 256
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

	readBufferSize  int
	writeBufferSize int

	// udpPacket travels by VALUE: a pointer channel would force one 64B heap
	// allocation per received packet (~680 allocs/s measured in production,
	// 34% of the process's total alloc_space), while a buffered channel send
	// memmoves the struct into the ring buffer with zero heap traffic.
	recvQueue chan udpPacket

	ctx    context.Context
	cancel context.CancelFunc
}

type udpPacket struct {
	Buf      []byte
	N        int
	Addr     net.Addr
	AddrPort netip.AddrPort
	Err      error
}

type dialFunc = func(addr net.Addr) (net.Conn, error)

func NewUDPHopPacketConn(addr *UDPHopAddr, hopInterval time.Duration, dialFunc dialFunc) (net.PacketConn, error) {
	if hopInterval == 0 {
		hopInterval = defaultHopInterval
	} else if hopInterval < 5*time.Second {
		return nil, errors.New("hop interval must be at least 5 seconds")
	}
	if addr.TotalPorts() == 0 {
		return nil, InvalidPortError{addr.PortStr}
	}

	curConn, err := dialFunc(addr.PickRandomAddr())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	hConn := &udpHopPacketConn{
		HopInterval: hopInterval,
		addr:        addr,
		dialFunc:    dialFunc,
		currentConn: curConn,
		recvQueue:   make(chan udpPacket, packetQueueSize),
		ctx:         ctx,
		cancel:      cancel,
	}
	go hConn.recvLoop(curConn)
	go hConn.hopLoop()
	return hConn, nil
}

func (u *udpHopPacketConn) recvLoop(conn net.Conn) {
	// The underlying socket is connected, so the remote is fixed for this
	// recvLoop's lifetime — resolve both addr forms once instead of per packet.
	remoteAddr := conn.RemoteAddr()
	var remoteAddrPort netip.AddrPort
	if ua, ok := remoteAddr.(*net.UDPAddr); ok {
		remoteAddrPort = ua.AddrPort()
	}
	for {
		buf := pool.GetBuffer(udpBufferSize)
		n, err := conn.Read(buf)
		if err != nil {
			pool.PutBuffer(buf)
			netErr, ok := errors.AsType[net.Error](err)
			if ok && netErr.Timeout() {
				// Only pass through timeout errors here, not permanent errors
				// like connection closed. Connection close is normal as we close
				// the old connection to exit this loop every time we hop.
				// A blocking send could park here forever on a full queue —
				// Close() unblocks conn.Read but not this send — so give the
				// notification a ctx.Done exit: at shutdown dropping it is fine.
				select {
				case u.recvQueue <- udpPacket{nil, 0, nil, netip.AddrPort{}, netErr}:
				case <-u.ctx.Done():
				}
			}
			if errors.Is(err, net.ErrClosed) {
				// Routine hop-close of a retired socket — the per-hop
				// release accounting.
				if logger.Logger.IsLevelEnabled(logrus.DebugLevel) {
					logger.Logger.WithField("local", conn.LocalAddr().String()).
						Debug("[udphop] recvLoop exited: conn closed")
				}
			} else if logger.Logger.IsLevelEnabled(logrus.WarnLevel) {
				logger.Logger.WithField("local", conn.LocalAddr().String()).
					WithField("err", err.Error()).
					Warn("[udphop] recvLoop exited on unexpected error")
			}
			return
		}
		select {
		case u.recvQueue <- udpPacket{buf, n, remoteAddr, remoteAddrPort, nil}:
			// Packet successfully queued
		default:
			// Queue is full, drop the packet
			pool.PutBuffer(buf)
		}
	}
}

// HopNow migrates the packet conn to a new random destination port right now,
// keeping the previous socket open to receive stragglers. It is the on-demand
// form of the periodic hop: the hysteria2 client calls it when the dae side
// retries a probe whose port just failed, so that retry does not land on the
// same port. The QUIC connection above is untouched, so no handshake is lost.
//
// The bool reports whether the conn can hop at all, which is always true here;
// it exists so wrappers that may hide a non-hopping conn underneath (obfs) can
// answer the same question honestly.
func (u *udpHopPacketConn) HopNow() bool {
	u.hop()
	return true
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
		prevLocal := u.prevConn.LocalAddr().String()
		if err := u.prevConn.Close(); err != nil {
			// fd release is the resource that must not leak here; a failed
			// close is the only silent way it could.
			if logger.Logger.IsLevelEnabled(logrus.WarnLevel) {
				logger.Logger.WithField("local", prevLocal).
					Warn("[udphop] failed to close prev conn")
			}
		}
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

// ReadFromAddrPort is the allocation-free read path consumed by the quic-go
// fork's basicConn.ReadPacket (it type-asserts this exact signature before
// falling back to ReadFrom). A successful return must carry a valid AddrPort:
// quic-go treats an invalid one as "fast path unsupported" and re-reads the
// socket via ReadFrom, silently dropping the packet. This holds because the
// underlying socket is dialed as "udp" — direct dialers always yield a
// *net.UDPAddr RemoteAddr. (Chained dialers that return custom Addr types
// never reach this code as valid UDP anyway.)
func (u *udpHopPacketConn) ReadFromAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	select {
	case <-u.ctx.Done():
		return 0, netip.AddrPort{}, net.ErrClosed
	case p := <-u.recvQueue:
		if p.Err != nil {
			return 0, netip.AddrPort{}, p.Err
		}
		n := copy(b, p.Buf[:p.N])
		pool.PutBuffer(p.Buf)
		return n, p.AddrPort, nil
	}
}

func (u *udpHopPacketConn) WriteTo(b []byte, _ net.Addr) (n int, err error) {
	if u.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	// Skip the remote check for now, always write to the connected server,
	// for the same reason as in ReadFrom.
	return u.currentConn.Write(b)
}

// WriteToAddrPort mirrors WriteTo: the underlying socket is connected, so the
// address is ignored and the packet goes to the connected peer. Together with
// ReadFromAddrPort it completes the AddrPort-flavored PacketConn shape
// (dae's PacketConnAddrPort; the quic-go fork may grow a write fast path).
func (u *udpHopPacketConn) WriteToAddrPort(b []byte, _ netip.AddrPort) (n int, err error) {
	return u.WriteTo(b, nil)
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

// oobWriteMsgUDP is the subset of *net.UDPConn that carries GSO/ECN
// ancillary data. Forwarding WriteMsgUDP's oob to the real socket is what
// keeps quic-go's GSO batching alive across the hop wrapper.
type oobWriteMsgUDP interface {
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error)
}

// ReadMsgUDP implements quic-go fork's OOBCapablePacketConn. quic-go's
// oobConn never calls this for reads (it uses ReadBatch via the unexported
// batchConn interface), but the method must exist so the type assertion in
// quic.wrapConn succeeds. It drains from the recvQueue to stay consistent
// with ReadFrom and avoid racing the recvLoop on the underlying socket.
func (u *udpHopPacketConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	_ = oob
	n, src, err := u.ReadFrom(b)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	udpAddr, _ := src.(*net.UDPAddr)
	if udpAddr == nil {
		udpAddr = &net.UDPAddr{}
	}
	return n, 0, 0, udpAddr, nil
}

// WriteMsgUDP implements quic-go fork's OOBCapablePacketConn. Forwarding to
// the underlying connected socket preserves the GSO/ECN ancillary data
// quic-go attaches, so a single sendmsg can segment many QUIC datagrams —
// this is the whole point of satisfying the interface. The addr argument is
// ignored: the underlying socket is connected to the active hop, and quic-go
// 's addr may lag behind an in-flight hop. A proxied (non-socket) transport
// degrades to a plain Write without GSO.
func (u *udpHopPacketConn) WriteMsgUDP(b, oob []byte, _ *net.UDPAddr) (n, oobn int, err error) {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.ctx.Err() != nil {
		return 0, 0, net.ErrClosed
	}
	if wc, ok := u.currentConn.(oobWriteMsgUDP); ok {
		// The socket is connected; a nil addr sends to the connected peer.
		return wc.WriteMsgUDP(b, oob, nil)
	}
	nn, err := u.currentConn.Write(b)
	return nn, 0, err
}

// ReadBatch implements quic-go fork's (unexported) batchConn interface via
// Go's structural typing. When present, quic-go's oobConn routes reads
// through it instead of per-packet ReadMsgUDP — and this is critical for
// port hopping: a kernel-bound batch reader (ipv4.NewPacketConn on the
// current fd) would pin itself to the first hop's fd and silently stop
// receiving after every hop. Draining the shared recvQueue stays correct
// across hops while still handing quic-go a batch of packets per wakeup.
func (u *udpHopPacketConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	_ = flags
	if len(ms) == 0 {
		return 0, nil
	}
	select {
	case <-u.ctx.Done():
		return 0, net.ErrClosed
	case p := <-u.recvQueue:
		if p.Err != nil {
			return 0, p.Err
		}
		count := u.fillBatchMessage(&ms[0], &p)
		// Drain any further queued packets without blocking so quic-go can
		// process a burst in a single receive-loop iteration.
		for count < len(ms) {
			select {
			case p := <-u.recvQueue:
				if p.Err != nil {
					return count, p.Err
				}
				count += u.fillBatchMessage(&ms[count], &p)
			default:
				return count, nil
			}
		}
		return count, nil
	}
}

// fillBatchMessage copies one queued packet into an ipv4.Message slot and
// recycles its pool buffer. Returns 1 on success, 0 if the caller provided
// no usable buffer (the packet is dropped either way).
func (u *udpHopPacketConn) fillBatchMessage(msg *ipv4.Message, p *udpPacket) int {
	if len(msg.Buffers) == 0 || len(msg.Buffers[0]) == 0 {
		pool.PutBuffer(p.Buf)
		return 0
	}
	n := copy(msg.Buffers[0], p.Buf[:p.N])
	pool.PutBuffer(p.Buf)
	msg.N = n
	msg.NN = 0
	msg.Flags = 0
	addr := p.Addr
	if addr == nil {
		u.connMutex.RLock()
		addr = u.currentConn.RemoteAddr()
		u.connMutex.RUnlock()
	}
	msg.Addr = addr
	return 1
}

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
