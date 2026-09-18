// Package coalesce batches the ciphertext records a TLS/utls layer emits
// per application write into a single socket write. crypto/tls and utls
// both issue one underlying Write per TLS record; without coalescing a
// 32KB application write costs three write syscalls. The drain points are
// designed around three invariants proven on the anytls path:
//
//   - Read flushes first: every write-then-wait-for-peer pattern (TLS
//     handshake waiting for ServerHello, KeyUpdate responses, alerts)
//     sends writes through the coalescer and then blocks on a read.
//   - Explicit Flush after each framed write burst covers write-only
//     streams that never read.
//   - Close flushes close_notify before closing.
//
// Port of koutbound 723da22 + e3596a5.
package coalesce

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

// Conn sits between crypto/tls and the real socket. crypto/tls writes
// one syscall per TLS record (91.5k write syscalls per GB at 32KB frames: two
// full 16KB records plus an orphan ~7B one). This layer accumulates the
// ciphertext records produced by a single upper-layer write burst and flushes
// them with one socket write, cutting syscalls per 32KB frame from three to
// one.
//
// Contract with the caller: the anytls session flushes after each framed
// write burst and on Close, so data never sits buffered past the caller's
// write return. Errors surface at flush time, which is safe: TLS cannot
// resume after a partial record write anyway.
type Conn struct {
	net.Conn

	mu  sync.Mutex
	buf []byte

	wdNano atomic.Int64 // write deadline as unix nanoseconds; 0 = none
}

func New(c net.Conn) *Conn {
	return &Conn{Conn: c}
}

// Write accumulates ciphertext and reports full success. The bytes are copied
// because crypto/tls reuses its record output buffers after Write returns.
//
// The backing storage comes from pool.GetBuffer and is returned to the pool on
// every Flush, so buffers recycle across connections instead of each TLS
// connection keeping a burst-sized allocation alive until GC (the top
// alloc_space site in dae_ppdn heap profiles: coalesce.(*Conn).Write). The
// buffer is never append-grown past its pooled capacity: growth goes through
// swapBuf so pooled slices keep their power-of-2 cap, as pool.PutBuffer
// requires.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.buf)+len(p) > cap(c.buf) {
		c.swapBuf(len(c.buf) + len(p))
	}
	c.buf = append(c.buf, p...)
	n := len(c.buf)
	c.mu.Unlock()
	if n > bufHardLimit {
		// Self-defense: if a caller ever forgets to flush, drop the
		// accumulation instead of growing without bound.
		_ = c.Flush()
	}
	return len(p), nil
}

const bufHardLimit = 128 << 10

// swapBuf replaces the backing buffer with a pooled one of at least n bytes,
// preserving any pending bytes. Called with c.mu held.
func (c *Conn) swapBuf(n int) {
	newBuf := pool.GetBuffer(n)[:len(c.buf)]
	copy(newBuf, c.buf)
	c.release()
	c.buf = newBuf
}

// release returns the backing buffer to the pool and empties the view.
// Called with c.mu held.
func (c *Conn) release() {
	if c.buf != nil {
		pool.PutBuffer(c.buf[:cap(c.buf)])
		c.buf = nil
	}
}

// Flush writes accumulated records with a single socket write.
func (c *Conn) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buf) == 0 {
		return nil
	}
	if wd := c.wdNano.Load(); wd != 0 && !time.Unix(0, wd).After(time.Now()) {
		c.release()
		return os.ErrDeadlineExceeded
	}
	_, err := c.Conn.Write(c.buf)
	c.release()
	return err
}

// SetWriteDeadline records the deadline for Flush and forwards it so the
// kernel enforces it during the flush write itself.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.wdNano.Store(0)
	} else {
		c.wdNano.Store(t.UnixNano())
	}
	return c.Conn.SetWriteDeadline(t)
}

// Read flushes any pending records before blocking on the socket. Every
// "write then wait for peer" pattern — the TLS handshake waiting for
// ServerHello, KeyUpdate responses, keepalives — sends its writes through the
// coalescer and then reads; without this hook those records would sit
// buffered forever. Write-only streams are covered by the session's explicit
// flush after each framed write burst.
func (c *Conn) Read(p []byte) (int, error) {
	if c.Pending() != 0 {
		if err := c.Flush(); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(p)
}

// Pending returns the number of buffered bytes (diagnostics/tests).
func (c *Conn) Pending() int {
	c.mu.Lock()
	n := len(c.buf)
	c.mu.Unlock()
	return n
}

// Close tears the connection down. The raw conn is closed FIRST, without
// taking mu: a flush can be blocked mid-write holding mu (a synchronous
// pipe in tests, or a full TCP send buffer when no caller deadline is
// armed), and closing the socket unblocks it and every waiter behind it.
// Pending bytes — at most a close_notify, since steady-state callers flush
// per burst — are dropped; that beats deadlocking the deadline escape
// hatches that call Close.
func (c *Conn) Close() error {
	return c.Conn.Close()
}

// CloseWrite flushes the coalesced records and then half-closes the underlying
// socket. net.Conn has no CloseWrite, so embedding it does not promote one: a
// caller that peels to this layer (Vision's direct mode, which writes its
// payload to exactly this conn, and dae's relay) would otherwise half-close
// nothing while the socket stays fully open. Flushing first matters here:
// everything written so far is still in c.buf, and a FIN that overtakes its
// own records would truncate them.
func (c *Conn) CloseWrite() error {
	if err := c.Flush(); err != nil {
		return err
	}
	return netproxy.ForwardCloseWrite(c.Conn)
}
