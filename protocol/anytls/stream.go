package anytls

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

type stream struct {
	*session
	id uint32

	writeMu sync.Mutex

	// Chunk-chain receive path: received pool buffers are stored directly
	// and returned to the pool when consumed by Read. No extra copy.
	readMu      sync.Mutex
	readChunks  [][]byte
	readChunkOff int
	readCond    *sync.Cond
	readEOF     bool
	readErr     error

	closed  atomic.Bool
	finSent atomic.Bool
}

func newStream(session *session, id uint32) *stream {
	s := &stream{
		session: session,
		id:      id,
	}
	s.readCond = sync.NewCond(&s.readMu)
	return s
}

func (c *stream) Write(b []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	frame := newFrame(cmdPSH, c.id)
	frame.data = b
	return writeFrame(c.session, frame)
}

func (c *stream) Read(b []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readChunks) == 0 && !c.readEOF && c.readErr == nil {
		c.readCond.Wait()
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.readEOF && len(c.readChunks) == 0 {
		return 0, io.EOF
	}

	total := 0
	for len(c.readChunks) > 0 && total < len(b) {
		chunk := c.readChunks[0][c.readChunkOff:]
		n := copy(b[total:], chunk)
		total += n
		c.readChunkOff += n
		if c.readChunkOff >= len(c.readChunks[0]) {
			pool.PutBuffer(c.readChunks[0])
			c.readChunks = c.readChunks[1:]
			c.readChunkOff = 0
		}
	}
	return total, nil
}

// pushData takes ownership of chunk (a pool buffer) and delivers it to the stream.
// The caller must not use chunk after this call.
func (c *stream) pushData(chunk []byte) {
	c.readMu.Lock()
	c.readChunks = append(c.readChunks, chunk)
	c.readCond.Signal()
	c.readMu.Unlock()
}

// terminate drains queued chunks and signals fatal error.
// Called from session.Close() while holding streamLock.
func (c *stream) terminate() {
	c.readMu.Lock()
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
	c.drainChunks()
	c.readEOF = true
	c.readCond.Broadcast()
	c.readMu.Unlock()
}

// drainChunks returns all unread chunk buffers to the pool.
// Must be called with readMu held.
func (c *stream) drainChunks() {
	for _, chunk := range c.readChunks {
		pool.PutBuffer(chunk)
	}
	c.readChunks = nil
	c.readChunkOff = 0
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
	if c.finSent.CompareAndSwap(false, true) {
		frame := newFrame(cmdFIN, c.id)
		_, _ = writeFrame(c.session, frame)
	}
	return nil
}

func (c *stream) LocalAddr() net.Addr {
	return c.session.conn.LocalAddr()
}

func (c *stream) RemoteAddr() net.Addr {
	return c.session.conn.RemoteAddr()
}

func (c *stream) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *stream) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
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

	// Wait until we have at least a 2-byte length prefix.
	for {
		avail := ps.chunkAvail()
		if avail >= 2 {
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
	if ps.chunkAvail() < 2 {
		return 0, netip.AddrPort{}, io.EOF
	}

	// Peek the 2-byte length prefix.
	var lenBuf [2]byte
	ps.peekChunk(lenBuf[:])
	length := binary.BigEndian.Uint16(lenBuf[:])

	// Wait for the full datagram.
	for {
		avail := ps.chunkAvail()
		if avail >= int(length)+2 {
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
	if ps.chunkAvail() < int(length)+2 {
		return 0, netip.AddrPort{}, io.ErrUnexpectedEOF
	}

	if len(p) < int(length) {
		return 0, netip.AddrPort{}, io.ErrShortBuffer
	}

	// Discard the 2-byte length prefix, then copy the payload.
	ps.discardChunk(2)
	n := ps.copyFromChunks(p[:length])
	return n, ps.addr, nil
}

// chunkAvail returns the total available bytes in the chunk chain.
// Must be called with readMu held.
func (ps *packetStream) chunkAvail() int {
	total := 0
	for _, ch := range ps.readChunks {
		total += len(ch)
	}
	return total - ps.readChunkOff
}

// peekChunk copies bytes from the chunk chain without consuming them.
// Must be called with readMu held and enough bytes available.
func (ps *packetStream) peekChunk(p []byte) {
	off := ps.readChunkOff
	need := len(p)
	for _, ch := range ps.readChunks {
		n := copy(p[len(p)-need:], ch[off:])
		need -= n
		if need == 0 {
			return
		}
		off = 0
	}
}

// discardChunk advances the read position by n bytes, returning consumed
// chunks to the pool.
// Must be called with readMu held and enough bytes available.
func (ps *packetStream) discardChunk(n int) {
	for n > 0 {
		chunk := ps.readChunks[0]
		avail := len(chunk) - ps.readChunkOff
		if n < avail {
			ps.readChunkOff += n
			return
		}
		n -= avail
		pool.PutBuffer(chunk)
		ps.readChunks = ps.readChunks[1:]
		ps.readChunkOff = 0
	}
}

// copyFromChunks copies n bytes from the chunk chain to p, consuming and
// returning chunks to the pool.
// Must be called with readMu held.
func (ps *packetStream) copyFromChunks(p []byte) int {
	total := 0
	for total < len(p) && len(ps.readChunks) > 0 {
		chunk := ps.readChunks[0][ps.readChunkOff:]
		n := copy(p[total:], chunk)
		total += n
		ps.readChunkOff += n
		if ps.readChunkOff >= len(ps.readChunks[0]) {
			pool.PutBuffer(ps.readChunks[0])
			ps.readChunks = ps.readChunks[1:]
			ps.readChunkOff = 0
		}
	}
	return total
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

		frame := newFrame(cmdPSH, ps.id)
		frame.data = data
		if _, err := writeFrame(ps.session, frame); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	data := pool.GetBuffer(2 + len(p))
	defer pool.PutBuffer(data)
	binary.BigEndian.PutUint16(data, uint16(len(p)))
	copy(data[2:], p)

	frame := newFrame(cmdPSH, ps.id)
	frame.data = data
	if _, err := writeFrame(ps.session, frame); err != nil {
		return 0, err
	}
	return len(p), nil
}
