package anytls

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// sessionConn is the session-as-conn fast path. Instead of the run() dispatch
// loop + per-stream chunkRing, the session's TCP stream is consumed inline by
// net.Conn.Read: PSH payloads are read directly into the caller's buffer
// (zero-copy when the whole payload fits), and control frames (padding,
// heartbeats, settings) are consumed on the spot.
//
// Invariants:
//   - Exactly one reader owns the underlying TCP stream: sessions used by
//     sessionConn never start run(), and a sessionConn is never mixed with
//     streams on the same session. The mode is fixed per Dialer (see
//     Feature1.SessionAsConn), so the two paths never share a session.
//   - A sessionConn is used by exactly one request at a time (the dialer
//     removes the session from the idle pool on checkout and manageSession
//     returns it on Close), mirroring stream checkout semantics.
//   - Stale data from a previous request on a reused session (in-flight
//     bytes at the time the previous conn sent FIN) is dropped by the
//     sid != c.id filter in Read, which keeps pool reuse safe.
//
// halfCloseGrace bounds how long the read side stays open after a
// half-close (CloseWrite). The anytls server closes the stream locally on
// FIN without ever echoing one back (sing-anytls closeLocally: "don't
// notify remote peer"), and only a server relay that finishes normally
// sends FIN — one whose upstream keeps the connection open never does.
// Without this bound the r2l relay parks for a full idle-timeout cycle
// per half-closed client disconnect, which re-creates the connection
// leak this whole effort set out to fix. Test-overridable.
var halfCloseGrace = 10 * time.Second

// ErrStreamRefused marks an application-level refusal (the server failed to
// dial the upstream target). The frame stream stays aligned — the session
// itself remains healthy and pool-worthy — so it is exempt from the
// readHadError sentinel.
var ErrStreamRefused = errors.New("anytls: server refused stream")

// Heartbeat note: startHeartbeat() stays active (write-only, unaffected by the
// missing run loop). Server-initiated HeartRequests are answered only when
// Read is running; for pooled idle sessions liveness is verified by Probe()
// on checkout, which is a pure write probe.
type sessionConn struct {
	*session
	id uint32

	// Frame reassembly state, so a Read interrupted by a deadline in the
	// middle of a header or payload resumes without losing alignment.
	hdr  rawHeader
	hdrN int // header bytes already consumed
	// pendRemaining is the unread tail of an oversized cmdPSH payload. The
	// direct-read design leaves those bytes on the TCP stream (no
	// intermediate buffer); they are consumed straight into the caller's
	// buffer before any new frame is parsed.
	pendRemaining int

	eof  bool        // our FIN received from the server
	dead atomic.Bool // protocol violation / misalignment; conn is unusable

	// finSent makes the client-side cmdFIN (CloseWrite / pool return)
	// idempotent: both paths write it, and a duplicated FIN for an
	// already-forgotten sid is harmless but noisy on the wire.
	finSent atomic.Bool

	// readHadError records that a Read ended in a transport error (deadline,
	// reset, ...). The stream may then sit mid-frame; such a session must
	// never re-enter the idle pool, or every later request on it reads a
	// shifted frame stream ("invalid cmd").
	readHadError atomic.Bool
	// Read/Close mutual exclusion. Read holds readMu across its whole body
	// — including the blocking conn reads — so Close can only inspect the
	// reassembly state after the in-flight Read has fully exited. A mutex
	// alone would make Close wait out the read's idle timeout (up to
	// DefaultTCPIdleTimeout), so Close evicts the parked Read first:
	// SetReadDeadline(now) MUST stay before the lock — moving it inside
	// deadlocks Close against the very read it needs to interrupt.
	// Single-reader invariant: exactly one goroutine (dae's r2l relay)
	// calls Read; the mutex only serializes that reader against Close.
	readMu sync.Mutex
	closed bool

	// halfClosedDeadline is the read-deadline ceiling armed by CloseWrite,
	// stored as unix nanos (0 = not half-closed). Every later
	// SetReadDeadline is clamped to it: the relay loop's per-read
	// re-arm must not resurrect a half-closed stream past the grace.
	halfClosedDeadline atomic.Int64

	closeOnce sync.Once
}

// newDirectConn opens the target address on this session and returns it
// directly as a net.Conn. Mirrors newStream's write path (batched
// settings+SYN+PSH on the first use of the connection) but registers no
// stream object.
func (s *session) newDirectConn(addr string) (*sessionConn, error) {
	if s.Closed() {
		return nil, net.ErrClosed
	}
	// Clear any stale deadline left by another goroutine before
	// session re-entry.
	_ = s.conn.SetDeadline(time.Time{})

	tgtAddr, err := socks.ParseAddr(addr)
	if err != nil {
		return nil, err
	}

	s.sid.Add(1)
	sid := s.sid.Load()

	if sid == 1 {
		settings := newFrame(cmdSettings, 0)
		settings.data = settingsBytes(s.GetPadding())
		syn := newFrame(cmdSYN, sid)
		initialData := newFrame(cmdPSH, sid)
		initialData.data = tgtAddr

		if _, err := writeFrames(s, settings, syn, initialData); err != nil {
			s.Close()
			return nil, err
		}
	} else {
		syn := newFrame(cmdSYN, sid)
		if _, err := writeFrame(s, syn); err != nil {
			s.Close()
			return nil, err
		}
		frame := newFrame(cmdPSH, sid)
		frame.data = tgtAddr
		if _, err := writeFrame(s, frame); err != nil {
			s.Close()
			return nil, err
		}
	}

	return &sessionConn{session: s, id: sid}, nil
}

func (c *sessionConn) Read(b []byte) (n int, err error) {
	// Any transport error (EOF excepted) leaves the frame stream at an
	// untrusted position: record it once, here, instead of at every error
	// return below. Close uses this to keep the session out of the pool.
	defer func() {
		if err != nil && err != io.EOF && !errors.Is(err, ErrStreamRefused) {
			c.readHadError.Store(true)
		}
	}()
	if len(b) == 0 {
		return 0, nil
	}
	// Hold the mutex for the whole Read, blocking reads included, so Close
	// can never inspect reassembly state mid-read. Close evicts the parked
	// Read via SetReadDeadline(now) before locking, so contention lasts
	// microseconds, not the read's idle timeout.
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed || c.dead.Load() {
		return 0, net.ErrClosed
	}
	// A previous error already broke frame alignment: allow no further
	// reads — by contract the connection is unusable once a Read fails.
	if c.readHadError.Load() {
		return 0, net.ErrClosed
	}
	if c.eof {
		return 0, io.EOF
	}
	// Resume the unread tail of an oversized payload left on the TCP stream
	// by a previous short read: no intermediate buffering, the bytes go
	// straight from the conn into the caller's buffer.
	if c.pendRemaining > 0 {
		n = min(len(b), c.pendRemaining)
		n, err = io.ReadFull(c.conn, b[:n])
		c.pendRemaining -= n
		return n, err
	}
	for {
		for c.hdrN < len(c.hdr) {
			n, err := io.ReadFull(c.conn, c.hdr[c.hdrN:])
			c.hdrN += n
			if err != nil {
				return 0, err
			}
		}
		c.hdrN = 0

		cmd := c.hdr.Cmd()
		sid := c.hdr.StreamID()
		length := int(c.hdr.Length())
		// Reject control frames that carry a payload — protocol violation
		// from a misbehaving server (same rule as run()).
		if length != 0 {
			switch cmd {
			case cmdFIN, cmdHeartRequest, cmdHeartResponse:
				return c.fatal(fmt.Errorf("anytls: invalid payload length %d for cmd %d", length, cmd))
			}
		}

		switch cmd {
		case cmdPSH:
			if length == 0 {
				continue
			}
			if sid != c.id {
				// In-flight bytes of an earlier request on this reused
				// connection: drop them to keep the new request isolated.
				if err := c.discard(length); err != nil {
					return 0, err
				}
				continue
			}
			// Read as much of the payload as fits, straight into the
			// caller's buffer — no intermediate GetBuffer copy even when
			// the payload is larger: its tail stays on the TCP stream,
			// accounted by pendRemaining, and resumes on the next Read.
			n, err := io.ReadFull(c.conn, b[:min(length, len(b))])
			c.pendRemaining = length - n
			if err != nil {
				// Short read + error is valid net.Conn semantics: the n
				// bytes are the caller's. The deferred hook flags the
				// connection unusable, so the session never re-enters the
				// pool with this tail pending.
				return n, err
			}
			return n, nil
		case cmdWaste:
			if err := c.discard(length); err != nil {
				return 0, err
			}
		case cmdFIN:
			if sid == c.id {
				c.eof = true
				return 0, io.EOF
			}
		case cmdHeartRequest:
			frame := newFrame(cmdHeartResponse, sid)
			if _, err := writeFrame(c.session, frame); err != nil {
				return c.fatal(fmt.Errorf("anytls: reply heartbeat: %w", err))
			}
		case cmdHeartResponse:
			// Probe replies; nothing to do.
		case cmdSYNACK:
			if length > 0 {
				buf := pool.GetBuffer(length)
				_, err := io.ReadFull(c.conn, buf)
				if err != nil {
					pool.PutBuffer(buf)
					return 0, err
				}
				if sid == c.id {
					msg := string(buf)
					pool.PutBuffer(buf)
					// Application-level refusal: the frame was consumed in
					// full, the stream stays aligned, and the server closes
					// only this stream — the session remains reusable. The
					// (now stale) FIN for sid is skipped by the sid filter
					// on the next checkout.
					return 0, fmt.Errorf("%w: %s", ErrStreamRefused, msg)
				}
				pool.PutBuffer(buf)
			}
		case cmdAlert:
			if length > 0 {
				buf := pool.GetBuffer(length)
				_, err := io.ReadFull(c.conn, buf)
				if err != nil {
					pool.PutBuffer(buf)
					return 0, err
				}
				slog.Error("[Alert]", slog.String("msg", string(buf)))
				pool.PutBuffer(buf)
			}
		case cmdUpdatePaddingScheme:
			if length > 0 {
				buf := pool.GetBuffer(length)
				_, err := io.ReadFull(c.conn, buf)
				if err != nil {
					pool.PutBuffer(buf)
					return 0, err
				}
				if padding := NewPaddingFactory(buf); padding != nil {
					c.SetPadding(padding)
				}
				pool.PutBuffer(buf)
			}
			// While the session idles in the pool nothing reads the TCP
			// stream, so a scheme pushed mid-idle is only applied at the
			// next checkout. That is safe: anytls PSH frames carry their
			// padding length inline, so the peer parses whatever we pad
			// with — the window only means stale (less randomised)
			// padding, never corruption.
		case cmdServerSettings:
			if length > 0 {
				buf := pool.GetBuffer(length)
				_, err := io.ReadFull(c.conn, buf)
				if err != nil {
					pool.PutBuffer(buf)
					return 0, err
				}
				m := stringMapFromBytes(buf)
				if v, err := strconv.Atoi(m["v"]); err == nil {
					c.peerVersion = byte(v)
				}
				pool.PutBuffer(buf)
			}
		default:
			return c.fatal(fmt.Errorf("anytls: invalid cmd: %d", cmd))
		}
	}
}

func (c *sessionConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	return writeDataFrames(c.session, c.id, b, time.Time{})
}

func (c *sessionConn) Close() error {
	var firstErr error
	c.closeOnce.Do(func() {
		// Evict a Read parked mid-frame on the TCP stream BEFORE taking
		// readMu: Read holds that mutex across its blocking conn reads, so
		// locking first would stall Close until the read's idle timeout
		// expires. The deadline makes the in-flight Read return at once,
		// releasing the lock microseconds later. (Do not reorder.)
		_ = c.conn.SetReadDeadline(time.Now())

		c.readMu.Lock()
		defer c.readMu.Unlock()
		// The in-flight Read (if any) has exited; from here the reassembly
		// state is safe to inspect. Post-Close Reads are rejected by the
		// closed flag; dead is kept in lockstep for paths that check it.
		c.closed = true
		c.dead.Store(true)

		// Two states leave the stream off a frame boundary and make the
		// session unfit for the idle pool:
		//   - readHadError: a Read ended in a transport error or protocol
		//     violation (sentinel set by Read's deferred hook). markDead is
		//     idempotent for the fatal path, which already tore the session
		//     down.
		//   - pendRemaining > 0: the direct-read design left an oversized
		//     payload's tail on the TCP stream and the caller gave up
		//     before consuming it.
		if !c.eof {
			if c.readHadError.Load() || c.pendRemaining > 0 {
				c.markDead()
				return
			}
			// Tell the server this stream is done, best effort. A failed
			// FIN can mean a partial frame on the wire — the stream is
			// then mid-frame and the next checkout would parse garbage
			// (the write path never sets readHadError), so the session
			// must die here, not return to the pool.
			if err := c.sendFin(); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				c.markDead()
				return
			}
		}
		// Return the session to the idle pool (also clears deadlines).
		c.session.removeStream(c.id)
	})
	return firstErr
}

// sendFin writes this stream's cmdFIN exactly once. Both the half-close
// (CloseWrite) and the pool-return (Close) paths use it; the server drops a
// FIN for an already-forgotten sid, but one frame is cleaner on the wire.
func (c *sessionConn) sendFin() error {
	// Idempotent, but only on SUCCESS: the flag is set after the write
	// commits, so a failed FIN (dead conn) can be retried by a later
	// Close without being swallowed by the dedup gate. The write carries
	// its own short deadline — inheriting a stale expired one from an
	// idle relay previously made the FIN fail silently and left r2l
	// parked for a full idle-timeout cycle.
	if c.finSent.Load() {
		return nil
	}
	frame := newFrame(cmdFIN, c.id)
	if _, err := writeFrameWithDeadline(c.session, frame, time.Now().Add(frameWriteTimeout)); err != nil {
		return err
	}
	c.finSent.Store(true)
	return nil
}

// CloseWrite implements netproxy.CloseWriter: dae's relay calls it when the
// client half-closes (the l2r direction ends without error). It tells the
// server this stream's client side is done, so the server can close its
// upstream and finish the response. Reading stays open — but bounded: the
// anytls server never echoes a FIN for a half-close (it closes the stream
// locally without notifying the peer), so an unbounded wait would park the
// r2l relay for the full idle timeout on every client disconnect. The
// grace deadline is the single backstop, and it needs no force-close
// timer, which would kill active transfers outright:
//   - soft: arm the conn read deadline at now+halfCloseGrace. A server
//     still sending overrides it on the relay loop's next per-read
//     deadline re-arm, so active transfers are unaffected; the response
//     completing makes the server relay finish and send a real FIN.
//   - live vs silent: the only window where the grace gets overridden
//     before firing is a relay mid-write — a live stream, exactly the one
//     that doesn't need the backstop; a silent server always has the
//     deadline armed on its parked Read.
//
// A grace timeout always leaves the session mid-frame-risky (readHadError),
// so Close marks the session dead rather than pooling it; the pool
// replenisher absorbs that cost.
func (c *sessionConn) CloseWrite() error {
	if err := c.sendFin(); err != nil {
		return err
	}
	d := time.Now().Add(halfCloseGrace)
	c.halfClosedDeadline.Store(d.UnixNano())
	_ = c.conn.SetReadDeadline(d)
	return nil
}

func (c *sessionConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *sessionConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *sessionConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *sessionConn) SetReadDeadline(t time.Time) error {
	// After a half-close the stream is terminal: cap every re-arm at the
	// grace deadline. Without this, relay data still in flight when the
	// client disconnects tricks the relay loop into re-arming the full
	// idle timeout; the server then goes silent forever (it never echoes
	// a FIN for a half-close) and the relay parks for that whole timeout.
	if hd := c.halfClosedDeadline.Load(); hd != 0 {
		if grace := time.Unix(0, hd); t.After(grace) {
			t = grace
		}
	}
	return c.conn.SetReadDeadline(t)
}

func (c *sessionConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// discard skips a payload. An interrupted discard loses bytes that have no
// owner, which would desynchronize the frame stream — treat as fatal.
func (c *sessionConn) discard(n int) error {
	if _, err := io.CopyN(io.Discard, c.conn, int64(n)); err != nil {
		c.markDead()
		return fmt.Errorf("anytls: discard %d bytes: %w", n, err)
	}
	return nil
}

// fatal marks the connection unusable and tears the session down.
func (c *sessionConn) fatal(err error) (int, error) {
	c.markDead()
	return 0, err
}

func (c *sessionConn) markDead() {
	c.dead.Store(true)
	c.session.Close()
}
