package anytls

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

type session struct {
	conn     net.Conn
	connLock sync.Mutex

	// flusher, when set, drains the TLS record coalescer sitting under
	// conn after each framed write burst and before the raw close, so a
	// burst leaves in one socket write and no record sits buffered past
	// the caller's write return.
	flusher interface{ Flush() error }

	streams    map[uint32]*stream
	streamLock sync.RWMutex

	padding     *atomic.Pointer[paddingFactory]
	sendPadding bool
	pktCounter  atomic.Uint32
	peerVersion byte

	seq             uint64
	sid             atomic.Uint32
	closed          atomic.Bool
	closeStreamChan chan uint32

	heartbeatInterval time.Duration
	idleSince         time.Time

	// dialLatency is the TCP+TLS handshake duration measured when this
	// session was created. Used to prefer faster sessions during pool
	// selection and to evict slower sessions during cleanup.
	dialLatency time.Duration
}

func newSession(conn net.Conn, seq uint64) *session {
	padding := &atomic.Pointer[paddingFactory]{}
	padding.Store(DefaultPaddingFactory.Load())
	s := &session{
		conn:            conn,
		streams:         map[uint32]*stream{},
		padding:         padding,
		seq:             seq,
		closeStreamChan: make(chan uint32),
		sendPadding:     true,
	}
	return s
}

func (s *session) newStream(addr string) (*stream, error) {
	if s.Closed() {
		return nil, net.ErrClosed
	}
	// Clear any stale deadline left by another goroutine before
	// session re-entry. DAE sets its own deadlines on the returned
	// stream afterwards.
	_ = s.conn.SetDeadline(time.Time{})

	tgtAddr, err := socks.ParseAddr(addr)
	if err != nil {
		return nil, err
	}

	s.sid.Add(1)
	sid := s.sid.Load()

	// Batch settings+SYN+PSH into one write for the first stream to save
	// an RTT and a TLS encoding. Subsequent streams send settings only
	// once (as part of the first stream batch) followed by SYN+PSH.
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
		frame := newFrame(cmdSYN, sid)
		if _, err := writeFrame(s, frame); err != nil {
			s.Close()
			return nil, err
		}
		frame = newFrame(cmdPSH, sid)
		frame.data = tgtAddr
		if _, err := writeFrame(s, frame); err != nil {
			s.Close()
			return nil, err
		}
	}

	stream := newStream(s, sid)
	s.streamLock.Lock()
	s.streams[sid] = stream
	s.streamLock.Unlock()

	return stream, nil
}

func (s *session) newPacketStream(addr, packetAddr string) (*packetStream, error) {
	stream, err := s.newStream(addr)
	if err != nil {
		return nil, err
	}
	ap, err := netip.ParseAddrPort(packetAddr)
	if err != nil {
		return nil, err
	}
	return &packetStream{
		stream: stream,
		addr:   ap,
	}, nil
}

func (s *session) removeStream(sid uint32) {
	// Hold streamLock across the close check + send so Close cannot
	// observe the lock release and close the channel before we send.
	// Close also holds streamLock while it closes closeStreamChan.
	s.streamLock.Lock()
	defer s.streamLock.Unlock()

	delete(s.streams, sid)

	// Clear any deadlines the stream set on the underlying connection.
	_ = s.conn.SetDeadline(time.Time{})

	if s.closed.Load() {
		return
	}
	// Blocking send: a dropped notification would leave the session idle but
	// untracked (never added to idleSessions), so cleanupIdleSessions would
	// never reap it. manageSession is always draining, so this never blocks
	// for long.
	s.closeStreamChan <- sid
}

func (s *session) run() error {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[Panic]", slog.String("stack", string(debug.Stack())))
		}
	}()
	defer s.Close()

	var header rawHeader
	for {
		if s.Closed() {
			return net.ErrClosed
		}
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			return err
		}
		sid := header.StreamID()
		length := int(header.Length())
		cmd := header.Cmd()
		// Reject control frames that carry a payload — these are protocol
		// violations indicating a misbehaving server.
		if length != 0 {
			switch cmd {
			case cmdFIN, cmdHeartRequest, cmdHeartResponse:
				return fmt.Errorf("invalid payload length %d for cmd %d", length, cmd)
			}
		}
		switch cmd {
		case cmdWaste:
			if _, err := io.CopyN(io.Discard, s.conn, int64(length)); err != nil {
				return err
			}
		case cmdPSH:
			// Ignore empty PSH frames — they indicate padding only and
			// carry no payload.
			if length == 0 {
				continue
			}
			buf := pool.GetBuffer(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.PutBuffer(buf)
				return err
			}
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if !ok {
				pool.PutBuffer(buf)
				continue
			}
			// pushData takes ownership of buf; must not Put it.
			stream.pushData(buf)
		case cmdAlert:
			buf := pool.GetBuffer(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.PutBuffer(buf)
				return err
			}
			slog.Error("[Alert]", slog.String("msg", string(buf)))
			pool.PutBuffer(buf)
		case cmdFIN:
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				stream.remoteClose()
			}
		case cmdUpdatePaddingScheme:
			if length > 0 {
				buf := pool.GetBuffer(length)
				if _, err := io.ReadFull(s.conn, buf); err != nil {
					pool.PutBuffer(buf)
					return err
				}
				if padding := NewPaddingFactory(buf); padding != nil {
					s.SetPadding(padding)
				}
				pool.PutBuffer(buf)
			}
		case cmdSYNACK:
			if length > 0 {
				buf := pool.GetBuffer(length)
				if _, err := io.ReadFull(s.conn, buf); err != nil {
					pool.PutBuffer(buf)
					return err
				}
				s.streamLock.RLock()
				stream, ok := s.streams[sid]
				s.streamLock.RUnlock()
				if ok {
					stream.Close()
				}
				pool.PutBuffer(buf)
			}
		case cmdServerSettings:
			if length > 0 {
				buffer := pool.GetBuffer(length)
				if _, err := io.ReadFull(s.conn, buffer); err != nil {
					pool.PutBuffer(buffer)
					return err
				}
				m := stringMapFromBytes(buffer)
				if v, err := strconv.Atoi(m["v"]); err == nil {
					s.peerVersion = byte(v)
				}
				pool.PutBuffer(buffer)
			}
		case cmdHeartRequest:
			frame := newFrame(cmdHeartResponse, sid)
			if _, err := writeFrameWithDeadline(s, frame, time.Now().Add(frameWriteTimeout)); err != nil {
				return err
			}
		case cmdHeartResponse:
		default:
			return fmt.Errorf("invalid cmd: %d", header.Cmd())
		}
	}
}

// Probe sends a lightweight heartbeat frame to verify the underlying connection
// is still alive. It returns nil if the write succeeds.
func (s *session) Probe() error {
	// The probe write carries its OWN deadline and overrides whatever write
	// deadline is on the conn. It must never CLEAR one: the heartbeat fires
	// every tick, often while a checked-out session's relay is mid-transport
	// — clearing the READ deadline disarmed the relay reader's idle timeout
	// (the production goroutine leak), and clearing the WRITE deadline
	// turned a queued writer's bounded timeout into an infinite block.
	// Overriding with a fresh future deadline keeps every in-flight write
	// bounded; the deadline lingers afterwards until the next write's own
	// deadline overrides it (writeConnWithDeadline no longer defer-clears).
	frame := newFrame(cmdHeartRequest, 0)
	_, err := writeFrameWithDeadline(s, frame, time.Now().Add(frameWriteTimeout))
	return err
}

// startHeartbeat launches a periodic heartbeat goroutine that sends
// cmdHeartRequest frames to keep the session alive and detect dead
// connections early.
func (s *session) startHeartbeat() {
	if s.heartbeatInterval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(s.heartbeatInterval)
		defer ticker.Stop()
		for range ticker.C {
			if s.Closed() {
				return
			}
			// No timeout special-case: Probe carries its own deadline, so
			// a timeout is a genuinely stalled connection (or one whose
			// conn died under us) — not a stale-deadline artifact to wipe.
			if err := s.Probe(); err != nil {
				s.Close()
				return
			}
		}
	}()
}

// ActiveStreams returns the number of currently open streams on this session.
func (s *session) ActiveStreams() int {
	s.streamLock.RLock()
	defer s.streamLock.RUnlock()
	return len(s.streams)
}

func (s *session) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.streamLock.Lock()
		for i := range s.streams {
			s.streams[i].terminate()
		}
		s.streams = make(map[uint32]*stream)
		// Hold streamLock while closing the channel: removeStream
		// holds the same lock across its closed-check + send, so this
		// cannot interleave between its check and send.
		close(s.closeStreamChan)
		s.streamLock.Unlock()
		// Drain the coalescer before the raw close: Conn.Close itself no
		// longer flushes (a blocked flush must not delay teardown), so a
		// pending close_notify or final frame is pushed here instead.
		if s.flusher != nil {
			_ = s.flusher.Flush()
		}
		return s.conn.Close()
	}
	return nil
}

func (s *session) Closed() bool {
	return s.closed.Load()
}

func (s *session) SetPadding(padding *paddingFactory) {
	s.padding.Store(padding)
}

func (s *session) GetPadding() *paddingFactory {
	return s.padding.Load()
}

func (s *session) writeConn(b []byte) (n int, err error) {
	return s.writeConnWithDeadline(b, time.Time{})
}

func (s *session) writeConnWithDeadline(b []byte, deadline time.Time) (n int, err error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	s.connLock.Lock()
	defer s.connLock.Unlock()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	if !deadline.IsZero() {
		if !deadline.After(time.Now()) {
			return 0, os.ErrDeadlineExceeded
		}
		if err := s.conn.SetWriteDeadline(deadline); err != nil {
			return 0, err
		}
		// Deliberately no defer-clear here. The deadline belongs to this
		// write and lingers until the next explicitly-deadlined write
		// overrides it. Clearing it on the way out would disarm an
		// in-flight writer that armed its own deadline and is queued
		// behind connLock (the write-side twin of the original probe
		// leak). Every writer either carries its own deadline (Probe,
		// sendFin, writeConnWithDeadline callers) or follows dae's
		// set-conn-deadline-then-Write pattern (sessionConn.Write), so a
		// lingering future deadline is always overridden before reuse.
	}
	n, err = s.writeConnLocked(b)
	if err != nil {
		return n, err
	}
	// Drain the TLS record coalescer so the burst leaves in one socket
	// write. Without this the caller believes the data is out while
	// records sit in the coalescing buffer.
	if s.flusher != nil {
		if ferr := s.flusher.Flush(); ferr != nil {
			return n, ferr
		}
	}
	return n, nil
}

func (s *session) writeConnLocked(b []byte) (n int, err error) {
	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.GetPadding()
		if pkt < paddingF.Stop {
			pktSizes := paddingF.GenerateRecordPayloadSizes(pkt)
			for _, l := range pktSizes {
				remainPayloadLen := len(b)
				if l == CheckMark {
					if remainPayloadLen == 0 {
						break
					}
					continue
				}
				if remainPayloadLen > l {
					wn, err := iout.WriteFull(s.conn, b[:l])
					n += wn
					if err != nil {
						return n, err
					}
					b = b[l:]
				} else if remainPayloadLen > 0 {
					paddingLen := l - remainPayloadLen - headerOverHeadSize
					if paddingLen > 0 {
						if paddingLen > maxFramePayloadSize {
							paddingLen = maxFramePayloadSize
						}
						combined := pool.GetBuffer(len(b) + headerOverHeadSize + paddingLen)
						copy(combined, b)
						fillWasteFrame(combined[len(b):], paddingLen)
						wn, err := iout.WriteFull(s.conn, combined)
						pool.PutBuffer(combined)
						if wn > remainPayloadLen {
							wn = remainPayloadLen
						}
						n += wn
						if err != nil {
							return n, err
						}
					} else {
						wn, err := iout.WriteFull(s.conn, b)
						n += wn
						if err != nil {
							return n, err
						}
					}
					b = nil
				} else {
					if l > maxFramePayloadSize {
						l = maxFramePayloadSize
					}
					padding := pool.GetBuffer(headerOverHeadSize + l)
					fillWasteFrame(padding, l)
					_, err = iout.WriteFull(s.conn, padding)
					pool.PutBuffer(padding)
					if err != nil {
						return n, err
					}
					b = nil
				}
			}
			if len(b) == 0 {
				return n, nil
			}
			n2, err := iout.WriteFull(s.conn, b)
			return n + n2, err
		}
		s.sendPadding = false
	}

	return iout.WriteFull(s.conn, b)
}

func fillWasteFrame(frame []byte, payloadLen int) {
	clear(frame)
	frame[0] = cmdWaste
	binary.BigEndian.PutUint32(frame[1:5], 0)
	binary.BigEndian.PutUint16(frame[5:7], uint16(payloadLen))
}
