package anytls

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

type session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*stream
	streamLock sync.RWMutex

	padding     atomic.Value
	sendPadding bool
	pktCounter  atomic.Uint32
	peerVersion byte

	seq             uint64
	sid             atomic.Uint32
	closed          atomic.Bool
	closeStreamChan chan uint32

	heartbeatInterval time.Duration
	idleSince         time.Time
}

func newSession(conn net.Conn, seq uint64) *session {
	s := &session{
		conn:            conn,
		streams:         map[uint32]*stream{},
		seq:             seq,
		closeStreamChan: make(chan uint32),
		sendPadding:     true,
	}
	s.padding.Store(DefaultPaddingFactory.Load())
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
	s.sid.Add(1)
	sid := s.sid.Load()

	frame := newFrame(cmdSettings, sid)
	frame.data = settingsBytes(s.GetPadding())
	if _, err := writeFrame(s, frame); err != nil {
		s.Close()
		return nil, err
	}

	frame = newFrame(cmdSYN, sid)
	if _, err := writeFrame(s, frame); err != nil {
		s.Close()
		return nil, err
	}

	tgtAddr, err := socks.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	frame = newFrame(cmdPSH, sid)
	frame.data = tgtAddr
	if _, err := writeFrame(s, frame); err != nil {
		s.Close()
		return nil, err
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
	select {
	case s.closeStreamChan <- sid:
	default:
	}
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
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Transient timeout from a stream deadline on s.conn.
				_ = s.conn.SetReadDeadline(time.Time{})
				continue
			}

			return err
		}
		sid := header.StreamID()
		length := int(header.Length())
		switch header.Cmd() {
		case cmdWaste:
			if _, err := io.CopyN(io.Discard, s.conn, int64(length)); err != nil {
				return err
			}
		case cmdPSH:
			buf := pool.GetBuffer(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.PutBuffer(buf)
				return err
			}
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				// pushData takes ownership of buf; must not Put it.
				stream.pushData(buf)
			} else {
				pool.PutBuffer(buf)
			}
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
				updatePaddingScheme(buf)
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
			if _, err := writeFrame(s, frame); err != nil {
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
	// Clear any stale deadline before probing — this is the first
	// write when pulling a session from the idle pool.
	_ = s.conn.SetDeadline(time.Time{})
	frame := newFrame(cmdHeartRequest, 0)
	_, err := writeFrame(s, frame)
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
			if err := s.Probe(); err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					_ = s.conn.SetWriteDeadline(time.Time{})
					continue
				}
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
	return s.padding.Load().(*paddingFactory)
}

func (s *session) writeConn(b []byte) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

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
					_, err = s.conn.Write(b[:l])
					if err != nil {
						return 0, err
					}
					n += l
					b = b[l:]
				} else if remainPayloadLen > 0 {
					paddingLen := l - remainPayloadLen - headerOverHeadSize
					if paddingLen > 0 {
						padding := pool.GetBuffer(headerOverHeadSize + paddingLen)
						padding[0] = cmdWaste
						binary.BigEndian.PutUint32(padding[1:5], 0)
						binary.BigEndian.PutUint16(padding[5:7], uint16(paddingLen))
						b = slices.Concat(b, padding)
						pool.PutBuffer(padding)
					}
					_, err = s.conn.Write(b)
					if err != nil {
						return 0, err
					}
					n += remainPayloadLen
					b = nil
				} else {
					padding := pool.GetBuffer(headerOverHeadSize + l)
					padding[0] = cmdWaste
					binary.BigEndian.PutUint32(padding[1:5], 0)
					binary.BigEndian.PutUint16(padding[5:7], uint16(l))
					_, err = s.conn.Write(padding)
					pool.PutBuffer(padding)
					if err != nil {
						return 0, err
					}
					b = nil
				}
			}
			if len(b) == 0 {
				return n, nil
			}
			n2, err := s.conn.Write(b)
			return n + n2, err
		}
		s.sendPadding = false
	}

	return s.conn.Write(b)
}
