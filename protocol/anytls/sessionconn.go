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

	// readHadError records that a Read ended in a transport error (deadline,
	// reset, ...). The stream may then sit mid-frame; such a session must
	// never re-enter the idle pool, or every later request on it reads a
	// shifted frame stream ("invalid cmd").
	readHadError atomic.Bool
	// readEnter tracks the in-flight Read call. dae's relay loop bounds each
	// Read with a deadline and closes the conn while the peer-direction
	// reader may still be unwinding, so Close must wait for the in-flight
	// reader to exit before trusting the state above.
	readEnter sync.WaitGroup

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
	c.readEnter.Add(1)
	defer c.readEnter.Done()
	if c.dead.Load() {
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
		// Refuse new Reads, then unblock any Read still in flight. dae's
		// relay closes the conn while the peer-direction reader may still be
		// blocked mid-frame, so the reassembly state is only safe to inspect
		// after that reader exits.
		c.dead.Store(true)
		_ = c.conn.SetReadDeadline(time.Now())
		c.readEnter.Wait()

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
			// Tell the server this stream is done, best effort. The session
			// (and its TCP connection) stays alive and returns to the pool.
			frame := newFrame(cmdFIN, c.id)
			if _, err := writeFrame(c.session, frame); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		// Return the session to the idle pool (also clears deadlines).
		c.session.removeStream(c.id)
	})
	return firstErr
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
