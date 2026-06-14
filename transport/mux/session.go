package mux

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type session struct {
	conn    net.Conn
	writeMu sync.Mutex

	streams   map[uint16]*stream
	streamsMu sync.RWMutex

	nextID atomic.Uint32

	writeFailed atomic.Bool // set when openStream fails, prevents session reuse
	closed      atomic.Bool
	closeCh     chan struct{}
	idleTimeout time.Duration
	idleTimer   *time.Timer
	idleMu      sync.Mutex
}

func newSession(conn net.Conn, idleTimeout time.Duration) *session {
	setKeepAlive(conn, 30*time.Second)

	s := &session{
		conn:        conn,
		streams:     make(map[uint16]*stream),
		closeCh:     make(chan struct{}),
		idleTimeout: idleTimeout,
	}
	go s.run()
	return s
}

// setKeepAlive enables TCP keepalive on the underlying TCP connection,
// unwrapping TLS, uTLS and other intermediate layers.
func setKeepAlive(conn net.Conn, period time.Duration) {
	type keepAliver interface {
		SetKeepAlive(bool) error
		SetKeepAlivePeriod(time.Duration) error
	}
	for i := 0; i < 8; i++ {
		if k, ok := conn.(keepAliver); ok {
			_ = k.SetKeepAlive(true)
			_ = k.SetKeepAlivePeriod(period)
			return
		}
		if tc, ok := conn.(*tls.Conn); ok {
			conn = tc.NetConn()
			continue
		}
		if nc, ok := conn.(interface{ NetConn() net.Conn }); ok {
			conn = nc.NetConn()
			continue
		}
		if u, ok := conn.(interface{ Unwrap() net.Conn }); ok {
			conn = u.Unwrap()
			continue
		}
		break
	}
}

func (s *session) run() {
	defer s.Close()

	var (
		metaLen [2]byte
		id      [2]byte
		status  [2]byte
		dataLen [2]byte
	)

	for {
		if _, err := io.ReadFull(s.conn, metaLen[:]); err != nil {
			return
		}
		mLen := binary.BigEndian.Uint16(metaLen[:])
		if mLen > 512 {
			return
		}

		if _, err := io.ReadFull(s.conn, id[:]); err != nil {
			return
		}
		sid := binary.BigEndian.Uint16(id[:])

		if _, err := io.ReadFull(s.conn, status[:]); err != nil {
			return
		}
		opcode := status[0]
		opts := status[1]

		if mLen > 4 {
			if _, err := io.CopyN(io.Discard, s.conn, int64(mLen-4)); err != nil {
				return
			}
		}

		switch opcode {
		case SessionStatusKeepAlive:
			continue

		case SessionStatusKeep:
			if opts != OptionData {
				continue
			}
			if _, err := io.ReadFull(s.conn, dataLen[:]); err != nil {
				return
			}
			dLen := int(binary.BigEndian.Uint16(dataLen[:]))
			buf := make([]byte, dLen)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				return
			}
			s.streamsMu.RLock()
			st, ok := s.streams[sid]
			s.streamsMu.RUnlock()
			if ok {
				st.pushData(buf)
			}

		case SessionStatusEnd:
			s.streamsMu.Lock()
			if st, ok := s.streams[sid]; ok {
				delete(s.streams, sid)
				st.closeRemote()
			}
			empty := len(s.streams) == 0
			s.streamsMu.Unlock()
			if empty {
				s.onStreamsEmpty()
			}
		}
	}
}

// openStream sends a SessionStatusNew frame and returns a new stream.
func (s *session) openStream(network string, host string, port int) (*stream, error) {
	s.cancelIdleTimer()

	id := uint16(s.nextID.Add(1))
	if id == 0 {
		id = uint16(s.nextID.Add(1))
	}

	st := newStream(s, id)

	s.streamsMu.Lock()
	s.streams[id] = st
	s.streamsMu.Unlock()

	var netType byte = 0x01 // TCP
	if network == "udp" {
		netType = 0x02
	}

	b := make([]byte, 0, 128)
	b = append(b, 0, 0) // metaLen placeholder
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, SessionStatusNew, OptionNone)
	b = append(b, netType)
	b = binary.BigEndian.AppendUint16(b, uint16(port))
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append(b, 0x01) // IPv4
			b = append(b, ip4...)
		} else {
			b = append(b, 0x03) // IPv6
			b = append(b, ip.To16()...)
		}
	} else {
		b = append(b, 0x02) // domain
		b = append(b, byte(len(host)))
		b = append(b, []byte(host)...)
	}
	binary.BigEndian.PutUint16(b[:2], uint16(len(b)-2))

	s.writeMu.Lock()
	_, err := s.conn.Write(b)
	s.writeMu.Unlock()
	if err != nil {
		s.streamsMu.Lock()
		delete(s.streams, id)
		s.streamsMu.Unlock()
		s.writeFailed.Store(true) // prevent reuse, but don't kill active streams
		return nil, err
	}

	return st, nil
}

func (s *session) removeStream(id uint16) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	empty := len(s.streams) == 0
	s.streamsMu.Unlock()
	if empty {
		s.onStreamsEmpty()
	}
}

// ActiveStreams returns the number of currently open streams.

// onStreamsEmpty starts the idle timer if configured.
func (s *session) onStreamsEmpty() {
	s.writeFailed.Store(false) // all streams finished normally, session is healthy
	if s.idleTimeout > 0 {
		s.startIdleTimer()
	}
}

func (s *session) startIdleTimer() {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	s.idleTimer = time.AfterFunc(s.idleTimeout, func() {
		// Double-check: race with cancelIdleTimer could mean a new
		// stream arrived just as the timer fired. Only close if the
		// session is truly idle.
		s.streamsMu.RLock()
		empty := len(s.streams) == 0
		s.streamsMu.RUnlock()
		if empty {
			s.Close()
		}
	})
}

func (s *session) cancelIdleTimer() {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
}

func (s *session) ActiveStreams() int {
	s.streamsMu.RLock()
	n := len(s.streams)
	s.streamsMu.RUnlock()
	return n
}

func (s *session) writeData(id uint16, data []byte) (int, error) {
	frame := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(frame[0:2], 4)
	binary.BigEndian.PutUint16(frame[2:4], id)
	frame[4] = SessionStatusKeep
	frame[5] = OptionData
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(data)))
	copy(frame[8:], data)

	s.writeMu.Lock()
	_, err := s.conn.Write(frame)
	s.writeMu.Unlock()
	if err == nil {
		s.writeFailed.Store(false)
	}
	return len(data), err
}

func (s *session) writeEnd(id uint16) error {
	frame := make([]byte, 6)
	binary.BigEndian.PutUint16(frame[0:2], 4)
	binary.BigEndian.PutUint16(frame[2:4], id)
	frame[4] = SessionStatusEnd
	frame[5] = OptionNone

	s.writeMu.Lock()
	_, err := s.conn.Write(frame)
	s.writeMu.Unlock()
	if err == nil {
		s.writeFailed.Store(false)
	}
	return err
}

func (s *session) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		close(s.closeCh)
		s.cancelIdleTimer()

		s.streamsMu.Lock()
		for _, st := range s.streams {
			st.terminate()
		}
		s.streams = make(map[uint16]*stream)
		s.streamsMu.Unlock()

		return s.conn.Close()
	}
	return nil
}

func (s *session) IsClosed() bool {
	return s.closed.Load()
}

func (s *session) IsWriteFailed() bool {
	return s.writeFailed.Load()
}
