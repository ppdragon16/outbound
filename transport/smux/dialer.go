package smux

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	smuxcore "github.com/daeuniverse/outbound/transport/smux/smux"
)

const (
	ProtocolSmux = iota
	ProtocolYAMux
	ProtocolH2Mux
)

const (
	Version0 = iota
	Version1
)

const (
	flagUDP       = 0b01
	flagAddr      = 0b10
	statusSuccess = 0
	statusError   = 1
)

type Smux struct {
	Dialer         netproxy.Dialer
	PassthroughUdp bool

	// Concurrency is the max number of streams per session. 0 means unlimited.
	Concurrency int

	// IdleTimeout is the duration a session stays alive after its last stream
	// closes. 0 means sessions live forever.
	IdleTimeout time.Duration

	mu       sync.Mutex
	sessions []*smuxcore.Session

	idleTimers sync.Map // *smuxcore.Session → *time.Timer
}

type SmuxConfig struct {
	PassThroughUDP bool
}

func (s *SmuxConfig) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, error) {
	return &Smux{
		Dialer:         nextDialer,
		PassthroughUdp: s.PassThroughUDP,
	}, nil
}

func (s *Smux) Connect() (err error) {
	// Lazy initialization: the first DialContext will create a session.
	return nil
}

func (s *Smux) Disconnect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, sess := range s.sessions {
		sess.Close()
	}
	s.sessions = nil
	return nil
}

func (s *Smux) Alive() bool {
	return s.Dialer.Alive()
}

// getSession returns an available session from the pool, or creates a new one.
func (s *Smux) getSession(ctx context.Context) (*smuxcore.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Prune dead/full sessions and find a healthy, non-full one.
	var alive []*smuxcore.Session
	for _, sess := range s.sessions {
		if sess.IsClosed() || sess.IsStreamIDFull() {
			continue
		}
		alive = append(alive, sess)
		if s.Concurrency <= 0 || sess.NumStreams() < s.Concurrency {
			s.sessions = alive
			return sess, nil
		}
	}
	s.sessions = alive

	// No available session — create a new one.
	dialCtx, cancel := netproxy.NewDialTimeoutContextFrom(ctx)
	defer cancel()
	conn, err := s.Dialer.DialContext(dialCtx, "tcp", "sp.mux.sing-box.arpa:444")
	if err != nil {
		return nil, err
	}

	_, err = common.Invoke(dialCtx, func() (any, error) {
		return conn.Write([]byte{Version0, ProtocolSmux})
	}, func() {
		conn.Close()
	})
	if err != nil {
		return nil, err
	}

	session, err := smuxcore.Client(conn, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if s.IdleTimeout > 0 {
		session.OnIdle = func() {
			timer := time.AfterFunc(s.IdleTimeout, func() {
				s.idleTimers.Delete(session)
				if session.IsClosed() || session.NumStreams() > 0 {
					return
				}
				s.removeSession(session)
				session.Close()
			})
			s.idleTimers.Store(session, timer)
		}
	}

	s.sessions = append(s.sessions, session)
	return session, nil
}

// removeSession removes a session from the active pool.
// The session is expected to close itself via notifyReadError/notifyWriteError.
func (s *Smux) removeSession(sess *smuxcore.Session) {
	s.mu.Lock()
	for i, se := range s.sessions {
		if se == sess {
			s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
}

// cancelIdleTimer stops the pending idle timeout for a session, if any.
func (s *Smux) cancelIdleTimer(sess *smuxcore.Session) {
	if timer, ok := s.idleTimers.LoadAndDelete(sess); ok {
		timer.(*time.Timer).Stop()
	}
}

func (s *Smux) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		sess, err := s.getSession(ctx)
		if err != nil {
			return nil, err
		}
		s.cancelIdleTimer(sess)
		stream, err := sess.OpenStream()
		if err != nil {
			s.removeSession(sess)
			return nil, err
		}
		return &Conn{Conn: stream, addr: addr}, nil
	case "udp":
		conn, err := s.ListenPacket(ctx, addr)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr("udp", addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Smux) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	sess, err := s.getSession(ctx)
	if err != nil {
		return nil, err
	}
	s.cancelIdleTimer(sess)
	stream, err := sess.OpenStream()
	if err != nil {
		s.removeSession(sess)
		return nil, err
	}
	return &UDPConn{Conn: Conn{Conn: stream, addr: addr, udp: true, packetAddr: true}}, nil
}
