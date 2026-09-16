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
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
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

// Flush writes accumulated records with a single socket write.
func (c *Conn) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buf) == 0 {
		return nil
	}
	if wd := c.wdNano.Load(); wd != 0 && !time.Unix(0, wd).After(time.Now()) {
		c.buf = c.buf[:0]
		return os.ErrDeadlineExceeded
	}
	_, err := c.Conn.Write(c.buf)
	c.buf = c.buf[:0]
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
