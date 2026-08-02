package anytls

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

const chunkRingSize = 8

// chunkRing is a fixed-size ring buffer of pool-backed []byte chunks.
//
// Full is detected by buf[tail] != nil (slot already occupied);
// empty by buf[head] == nil (no data). Consumed slots are explicitly
// nilled so that the pool buffers they reference remain GC-visible.
//
// off tracks the byte offset within buf[head] — the next Read will
// start from buf[head][off] rather than the chunk boundary.
type chunkRing struct {
	buf  [][]byte
	head int // index of first valid chunk
	tail int // index of next write position
	cnt  int // number of queued chunks
	off  int // byte offset within buf[head]
}

func (r *chunkRing) push(chunk []byte) bool {
	if r.buf == nil {
		r.buf = make([][]byte, chunkRingSize)
	}
	if r.isFull() {
		return false
	}
	r.buf[r.tail] = chunk
	r.tail = (r.tail + 1) % len(r.buf)
	r.cnt++
	return true
}

func (r *chunkRing) pop() []byte {
	chunk := r.buf[r.head]
	r.buf[r.head] = nil
	r.head = (r.head + 1) % len(r.buf)
	r.cnt--
	return chunk
}

func (r *chunkRing) isFull() bool  { return r.buf[r.tail] != nil }
func (r *chunkRing) isEmpty() bool { return r.buf[r.head] == nil }

// available returns the number of readable bytes across all queued chunks,
// accounting for the offset within the first chunk.
func (r *chunkRing) available() int {
	if r.isEmpty() {
		return 0
	}
	total := 0
	for i, pos := 0, r.head; i < r.cnt; i++ {
		total += len(r.buf[pos])
		pos = (pos + 1) % len(r.buf)
	}
	return total - r.off
}

// read copies up to len(p) bytes from the ring into p, consuming them.
// Partially-consumed chunks stay in the ring; fully-consumed chunks are
// returned to the pool. Returns the number of bytes copied.
func (r *chunkRing) read(p []byte) int {
	total := 0
	for total < len(p) && !r.isEmpty() {
		chunk := r.buf[r.head][r.off:]
		n := copy(p[total:], chunk)
		total += n
		r.off += n
		if r.off >= len(r.buf[r.head]) {
			pool.PutBuffer(r.pop())
			r.off = 0
		}
	}
	return total
}

// drain calls fn on every queued chunk (typically pool.PutBuffer) and
// resets the ring to empty. The underlying array is retained for reuse.
func (r *chunkRing) drain(fn func([]byte)) {
	if r.buf == nil {
		return
	}
	for !r.isEmpty() {
		fn(r.pop())
	}
	r.off = 0
}

type stream struct {
	*session
	id uint32

	writeMu sync.Mutex

	// Chunk-chain receive path: received pool buffers are stored in a ring
	// buffer and returned to the pool when consumed by Read. No extra copy.
	readMu   sync.Mutex
	readRing chunkRing
	readCond *sync.Cond
	readEOF  bool
	readErr  error

	// readDeadline is the deadline for stream.Read calls.
	// A timer fires readCond.Signal when the deadline expires so that
	// Read (which blocks on readCond.Wait) can detect the timeout.
	readDeadline      time.Time
	readDeadlineTimer *time.Timer

	closed  atomic.Bool
	finSent atomic.Bool
}

func newStream(session *session, id uint32) *stream {
	s := &stream{
		session:  session,
		id:       id,
		readRing: chunkRing{buf: make([][]byte, chunkRingSize)},
	}
	s.readCond = sync.NewCond(&s.readMu)
	return s
}

func (c *stream) Write(b []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	return writeDataFrames(c.session, c.id, b, time.Time{})
}

func (c *stream) Read(b []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.readRing.isEmpty() && !c.readEOF && c.readErr == nil {
		if !c.readDeadline.IsZero() && time.Now().After(c.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		c.readCond.Wait()
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.readEOF && c.readRing.isEmpty() {
		return 0, io.EOF
	}

	n = c.readRing.read(b)
	c.readCond.Signal() // wake a blocked pushData
	return n, nil
}

// pushData takes ownership of chunk (a pool buffer) and delivers it to the stream.
// The caller must not use chunk after this call.
func (c *stream) pushData(chunk []byte) {
	c.readMu.Lock()
	for !c.readRing.push(chunk) {
		if c.readEOF || c.readErr != nil {
			pool.PutBuffer(chunk)
			c.readMu.Unlock()
			return
		}
		c.readCond.Wait()
	}
	c.readCond.Signal()
	c.readMu.Unlock()
}

// terminate drains queued chunks and signals fatal error.
// Called from session.Close() while holding streamLock.
func (c *stream) terminate() {
	c.readMu.Lock()
	c.stopReadDeadlineTimer()
	if c.readErr == nil {
		c.readErr = net.ErrClosed
	}
	c.readEOF = true
	c.readCond.Broadcast()
	c.drainChunks()
	c.readMu.Unlock()
}

// closeRead drains unread chunks and marks EOF. Used when the stream is
// closed locally or remotely — any buffered data is discarded since the
// caller has no way to read it anymore.
func (c *stream) closeRead() {
	c.readMu.Lock()
	c.stopReadDeadlineTimer()
	c.drainChunks()
	c.readEOF = true
	c.readCond.Broadcast()
	c.readMu.Unlock()
}

// stopReadDeadlineTimer stops the read deadline timer without discarding it
// so it can be reused on the next SetReadDeadline call.
// Must be called with readMu held.
func (c *stream) stopReadDeadlineTimer() {
	c.readDeadline = time.Time{}
	if c.readDeadlineTimer != nil {
		c.readDeadlineTimer.Stop()
	}
}

// drainChunks returns all unread chunk buffers to the pool.
// Must be called with readMu held.
func (c *stream) drainChunks() {
	c.readRing.drain(pool.PutBuffer)
}

func (c *stream) remoteClose() {
	if c.closed.CompareAndSwap(false, true) {
		c.session.removeStream(c.id)
		c.closeRead()
	}
}

func (c *stream) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.session.removeStream(c.id)
		if c.finSent.CompareAndSwap(false, true) {
			frame := newFrame(cmdFIN, c.id)
			_, _ = writeFrame(c.session, frame)
		}
		c.closeRead()
	}
	return nil
}

func (c *stream) CloseWrite() error {
	// The sing-anytls server never sends FIN in response to a client-
	// initiated close (closeLocally consumes dieOnce, blocking the
	// closeWithError -> streamClosed -> cmdFIN path).  Waiting for the
	// server to reply is therefore pointless — close the stream fully
	// and return the session to the idle pool immediately.
	return c.Close()
}

func (c *stream) LocalAddr() net.Addr {
	return c.session.conn.LocalAddr()
}

func (c *stream) RemoteAddr() net.Addr {
	return c.session.conn.RemoteAddr()
}

func (c *stream) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.conn.SetWriteDeadline(t)
}

// SetReadDeadline arms a timer that signals the read condition variable when
// the deadline expires, so that Read (which blocks on readCond.Wait) can
// detect the timeout. The timer is created once and reused via Reset.
func (c *stream) SetReadDeadline(t time.Time) error {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.readDeadline = t
	if t.IsZero() {
		c.stopReadDeadlineTimer()
		return nil
	}
	if c.readDeadlineTimer == nil {
		c.readDeadlineTimer = time.AfterFunc(time.Until(t), func() {
			c.readMu.Lock()
			c.readCond.Signal()
			c.readMu.Unlock()
		})
	} else {
		c.readDeadlineTimer.Reset(time.Until(t))
	}
	return nil
}

func (c *stream) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type packetStream struct {
	*stream

	addr         netip.AddrPort
	udpWriteAddr atomic.Bool
}

func (ps *packetStream) ReadFrom(p []byte) (int, net.Addr, error) {
	n, ap, err := ps.ReadFromAddrPort(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(ap), nil
}

func (ps *packetStream) ReadFromAddrPort(p []byte) (int, netip.AddrPort, error) {
	if ps.closed.Load() {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	ps.readMu.Lock()
	defer ps.readMu.Unlock()

	// Wait for and consume the 2-byte length prefix.
	for {
		if ps.readRing.available() >= 2 {
			break
		}
		if ps.readEOF || ps.readErr != nil {
			break
		}
		ps.readCond.Wait()
	}
	if ps.readErr != nil {
		return 0, netip.AddrPort{}, ps.readErr
	}
	if ps.readRing.available() < 2 {
		return 0, netip.AddrPort{}, io.EOF
	}

	var lenBuf [2]byte
	ps.readRing.read(lenBuf[:])
	length := binary.BigEndian.Uint16(lenBuf[:])

	// Wait for the full payload.
	for {
		if ps.readRing.available() >= int(length) {
			break
		}
		if ps.readEOF || ps.readErr != nil {
			break
		}
		ps.readCond.Wait()
	}
	if ps.readErr != nil {
		return 0, netip.AddrPort{}, ps.readErr
	}
	if ps.readRing.available() < int(length) {
		return 0, netip.AddrPort{}, io.ErrUnexpectedEOF
	}

	if len(p) < int(length) {
		return 0, netip.AddrPort{}, io.ErrShortBuffer
	}

	n := ps.readRing.read(p[:length])
	return n, ps.addr, nil
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

func (ps *packetStream) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ap, err := ToAddrPort(addr)
	if err != nil {
		return 0, err
	}
	return ps.WriteToAddrPort(p, ap)
}

func (ps *packetStream) WriteToAddrPort(p []byte, ap netip.AddrPort) (n int, err error) {
	if ps.closed.Load() {
		return 0, net.ErrClosed
	}
	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()

	if ps.udpWriteAddr.CompareAndSwap(false, true) {
		addr := ap.Addr()
		var tgtAddrLen int
		if addr.Is4() {
			tgtAddrLen = 7 // ATYP(1) + IPv4(4) + Port(2)
		} else {
			tgtAddrLen = 19 // ATYP(1) + IPv6(16) + Port(2)
		}
		data := pool.GetBuffer(1 + tgtAddrLen + 2 + len(p))
		defer pool.PutBuffer(data)
		data[0] = 1
		if addr.Is4() {
			data[1] = socks.ATypIP4
			ip4 := addr.As4()
			copy(data[2:6], ip4[:])
			binary.BigEndian.PutUint16(data[6:8], ap.Port())
		} else {
			data[1] = socks.ATypIP6
			ip16 := addr.As16()
			copy(data[2:18], ip16[:])
			binary.BigEndian.PutUint16(data[18:20], ap.Port())
		}
		binary.BigEndian.PutUint16(data[1+tgtAddrLen:], uint16(len(p)))
		copy(data[1+tgtAddrLen+2:], p)

		if _, err := writeDataFrames(ps.session, ps.id, data, time.Time{}); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	data := pool.GetBuffer(2 + len(p))
	defer pool.PutBuffer(data)
	binary.BigEndian.PutUint16(data, uint16(len(p)))
	copy(data[2:], p)

	if _, err := writeDataFrames(ps.session, ps.id, data, time.Time{}); err != nil {
		return 0, err
	}
	return len(p), nil
}
