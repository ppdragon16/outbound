package anytls

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
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
// Heartbeat note: startHeartbeat() stays active (write-only, unaffected by the
// missing run loop). Server-initiated HeartRequests are answered only when
// Read is running; for pooled idle sessions liveness is verified by Probe()
// on checkout, which is a pure write probe.
type sessionConn struct {
	*session
	id uint32

	// Frame reassembly state, so a Read interrupted by a deadline in the
	// middle of a header or payload resumes without losing alignment.
	hdr     rawHeader
	hdrN    int    // header bytes already consumed
	pendBuf []byte // pool buffer holding unread payload (valid segment)
	pendOff int    // next byte to return from pendBuf

	eof  bool // our FIN received from the server
	dead bool // protocol violation / misalignment; conn is unusable

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

func (c *sessionConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	// Resume any payload left over from a previous short read.
	if c.pendBuf != nil {
		n := copy(b, c.pendBuf[c.pendOff:])
		c.pendOff += n
		if c.pendOff == len(c.pendBuf) {
			pool.PutBuffer(c.pendBuf)
			c.pendBuf, c.pendOff = nil, 0
		}
		return n, nil
	}
	if c.dead {
		return 0, net.ErrClosed
	}
	if c.eof {
		return 0, io.EOF
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
			if length <= len(b) {
				// Fast path: read the payload straight into the caller's
				// buffer — no intermediate copy.
				n, err := io.ReadFull(c.conn, b[:length])
				if err == nil {
					return n, nil
				}
				if n > 0 {
					// Interrupted mid-payload (deadline): keep the bytes for
					// the next call so alignment is preserved.
					c.stash(b[:n])
					return n, err
				}
				return 0, err
			}
			// Payload larger than the caller's buffer: read it all into a
			// pool buffer and hand out slices.
			buf := pool.GetBuffer(length)
			n, err := io.ReadFull(c.conn, buf)
			if n > 0 {
				c.pendBuf, c.pendOff = buf[:n], 0
			}
			if err != nil {
				if c.pendBuf != nil {
					return 0, err // pending keeps the partial payload
				}
				pool.PutBuffer(buf)
				return 0, err
			}
			n2 := copy(b, buf)
			c.pendOff = n2
			return n2, nil
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
					return c.fatal(fmt.Errorf("anytls: server refused stream: %s", msg))
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
		// Tell the server this stream is done, best effort. The session
		// (and its TCP connection) stays alive and returns to the pool.
		if !c.eof {
			frame := newFrame(cmdFIN, c.id)
			if _, err := writeFrame(c.session, frame); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		c.releasePending()
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

// stash parks payload bytes already read into the caller's buffer after a
// mid-payload interruption, so the next Read resumes in order.
func (c *sessionConn) stash(data []byte) {
	buf := pool.GetBuffer(len(data))
	copy(buf, data)
	c.pendBuf, c.pendOff = buf[:len(data)], 0
}

func (c *sessionConn) releasePending() {
	if c.pendBuf != nil {
		pool.PutBuffer(c.pendBuf)
		c.pendBuf, c.pendOff = nil, 0
	}
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
	c.dead = true
	c.session.Close()
}
