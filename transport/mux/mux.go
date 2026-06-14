package mux

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

// Mux is a TCP multiplexing dialer compatible with Xray-core's mux protocol.
// It maintains a pool of sessions, each carrying multiple virtual connections
// (streams) over a single TCP connection, distinguished by session ID.
type Mux struct {
	protocol.StatelessDialer
	Addr           string
	PassthroughUdp bool

	// Concurrency is the max number of streams per session. 0 means unlimited.
	// When all sessions are full, a new physical connection is created.
	Concurrency int

	// IdleTimeout is the duration a session stays alive after its last stream
	// closes. 0 means sessions live forever.
	IdleTimeout time.Duration

	mu       sync.Mutex
	sessions []*session
}

func (s *Mux) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp", "udp":
		if network == "udp" && s.PassthroughUdp {
			return s.ParentDialer.DialContext(ctx, network, addr)
		}

		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("[Mux]: invalid addr %s: %w", addr, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("[Mux]: invalid port %s: %w", portStr, err)
		}

		// Retry once: if openStream fails (session dead), getSession
		// will skip the writeFailed session and give us a fresh one.
		for range 2 {
			sess, err := s.getSession(ctx)
			if err != nil {
				return nil, fmt.Errorf("[Mux]: dial to %s: %w", s.Addr, err)
			}
			stream, err := sess.openStream(network, host, port)
			if err == nil {
				return stream, nil
			}
		}
		return nil, fmt.Errorf("[Mux]: dial to %s: open stream failed after retry", s.Addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Mux) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	if s.PassthroughUdp {
		return s.ParentDialer.ListenPacket(ctx, addr)
	}
	return nil, fmt.Errorf("%w: mux+udp", netproxy.UnsupportedTunnelTypeError)
}

func (s *Mux) getSession(ctx context.Context) (*session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find an alive session that isn't full.
	for _, sess := range s.sessions {
		if !sess.IsClosed() && !sess.IsWriteFailed() && (s.Concurrency <= 0 || sess.ActiveStreams() < s.Concurrency) {
			return sess, nil
		}
	}

	// No available session — create a new one.
	conn, err := s.ParentDialer.DialContext(ctx, "tcp", s.Addr)
	if err != nil {
		return nil, err
	}

	sess := newSession(conn, s.IdleTimeout)
	s.sessions = append(s.sessions, sess)
	return sess, nil
}
