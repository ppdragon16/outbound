package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	protocol.Register("anytls", NewDialer)
}

type Dialer struct {
	protocol.StatelessDialer
	proxyAddress string
	key          []byte
	tlsConfig    *tls.Config

	sessionCounter atomic.Uint64

	mu           sync.Mutex
	idleSessions map[uint64]*session

	idleSessionCheckInterval time.Duration
	idleSessionTimeout       time.Duration
	minIdleSession           int
	heartbeatInterval        time.Duration

	ctx    context.Context
	cancel context.CancelFunc
}

const (
	defaultIdleSessionCheckInterval = 30 * time.Second
	defaultIdleSessionTimeout       = 60 * time.Second
	defaultMinIdleSession           = 10
)

func NewDialer(ParentDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	sum := sha256.Sum256([]byte(header.Password))

	// Read AnyTLS-specific config from Feature1, with defaults.
	checkInterval := defaultIdleSessionCheckInterval
	idleTimeout := defaultIdleSessionTimeout
	minIdle := defaultMinIdleSession
	if f, ok := header.Feature1.(*Feature1); ok && f != nil {
		if f.IdleSessionCheckInterval > 0 {
			checkInterval = f.IdleSessionCheckInterval
		}
		if f.IdleSessionTimeout > 0 {
			idleTimeout = f.IdleSessionTimeout
		}
		if f.MinIdleSession > 0 {
			minIdle = f.MinIdleSession
		}
	}

	// Heartbeat at a rate that ensures at least 2 probes within the idle
	// timeout window, clamped to [10s, 60s].
	heartbeatInterval := max(10*time.Second, min(60*time.Second, idleTimeout/3))

	ctx, cancel := context.WithCancel(context.Background())

	d := &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: ParentDialer,
		},
		proxyAddress:             header.ProxyAddress,
		key:                      sum[:],
		tlsConfig:                header.TlsConfig,
		idleSessions:             make(map[uint64]*session),
		idleSessionCheckInterval: checkInterval,
		idleSessionTimeout:       idleTimeout,
		minIdleSession:           minIdle,
		heartbeatInterval:        heartbeatInterval,
		ctx:                      ctx,
		cancel:                   cancel,
	}

	go d.idleCleanupLoop()

	return d, nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	switch network {
	case "tcp":
		s, err := d.getSession(ctx)
		if err != nil {
			return nil, err
		}
		return s.newStream(addr)
	case "udp":
		conn, err := d.ListenPacket(ctx, addr)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr(network, addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	s, err := d.getSession(ctx)
	if err != nil {
		return nil, err
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	return s.newPacketStream(net.JoinHostPort("sp.v2.udp-over-tcp.arpa", port), addr)
}

// pickIdleSession returns an idle session from the pool, or nil if none are
// available. The caller owns the returned session and must either use it or
// call Close() on it.
func (d *Dialer) pickIdleSession() *session {
	d.mu.Lock()
	defer d.mu.Unlock()
	for seq := range d.idleSessions {
		s := d.idleSessions[seq]
		if s.closed.Load() {
			delete(d.idleSessions, seq)
			continue
		}
		delete(d.idleSessions, seq)
		return s
	}
	return nil
}

func (d *Dialer) getSession(ctx context.Context) (*session, error) {
	// Try idle sessions first; probe each one for liveness before reusing.
	for {
		s := d.pickIdleSession()
		if s == nil {
			break
		}
		// Health probe: a successful write confirms the connection is alive.
		if err := s.Probe(); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Transient write timeout from leftover stream deadline.
				// Clear it and reuse anyway.
				_ = s.conn.SetDeadline(time.Time{})
				return s, nil
			}
			s.Close()
			continue
		}
		return s, nil
	}

	// No healthy idle session — create a new one.
	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, d.tlsConfig)

	buf := pool.GetBuffer(len(d.key) + 2)
	defer pool.PutBuffer(buf)
	copy(buf, d.key)
	binary.BigEndian.PutUint16(buf[len(d.key):], uint16(0))
	if _, err := tlsConn.Write(buf); err != nil {
		tlsConn.Close()
		return nil, err
	}

	seq := d.sessionCounter.Add(1)
	s := newSession(tlsConn, seq)
	s.heartbeatInterval = d.heartbeatInterval
	s.idleSince = time.Now()

	go d.manageSession(s, seq)
	go s.run()
	s.startHeartbeat()

	return s, nil
}

// manageSession returns the session to the idle pool each time a stream
// closes, and removes it from the pool when the session dies (signaled by
// closeStreamChan being closed). The for-range loop correctly handles
// session reuse across multiple streams.
func (d *Dialer) manageSession(s *session, seq uint64) {
	for range s.closeStreamChan {
		if s.closed.Load() {
			break
		}
		d.mu.Lock()
		s.idleSince = time.Now()
		d.idleSessions[seq] = s
		d.mu.Unlock()
	}
	// closeStreamChan was closed → session is dead, clean up.
	d.mu.Lock()
	delete(d.idleSessions, seq)
	d.mu.Unlock()
}

// idleCleanupLoop periodically scans the idle session pool and closes
// sessions that have been idle longer than idleSessionTimeout. It also
// enforces minIdleSession by closing the oldest idle sessions first.
func (d *Dialer) idleCleanupLoop() {
	ticker := time.NewTicker(d.idleSessionCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.cleanupIdleSessions()
		}
	}
}

func (d *Dialer) cleanupIdleSessions() {
	expireTime := time.Now().Add(-d.idleSessionTimeout)

	d.mu.Lock()

	// Collect expired sessions and count non-expired; clean dead entries.
	var expired []*session
	nonExpired := 0
	for seq, s := range d.idleSessions {
		if s.closed.Load() {
			delete(d.idleSessions, seq)
			continue
		}
		if s.ActiveStreams() > 0 {
			continue
		}
		if s.idleSince.Before(expireTime) {
			expired = append(expired, s)
		} else {
			nonExpired++
		}
	}

	if d.minIdleSession <= 0 || nonExpired >= d.minIdleSession {
		// Enough non-expired — close all expired, no sorting needed.
		for _, s := range expired {
			delete(d.idleSessions, s.seq)
		}
		d.mu.Unlock()
		for _, s := range expired {
			s.Close()
		}
	} else {
		// Need to keep some expired; sort newest-first, protect the freshest.
		slices.SortFunc(expired, func(a, b *session) int {
			return b.idleSince.Compare(a.idleSince)
		})
		n := min(d.minIdleSession-nonExpired, len(expired))
		for i, s := range expired {
			if i < n {
				s.idleSince = time.Now() // protect
			} else {
				delete(d.idleSessions, s.seq)
			}
		}
		d.mu.Unlock()
		for _, s := range expired[n:] {
			s.Close()
		}
	}
}

// Disconnect shuts down the dialer: stops the cleanup loop, closes all
// idle sessions, and disconnects the parent.
func (d *Dialer) Disconnect() error {
	d.cancel()

	d.mu.Lock()
	for seq, s := range d.idleSessions {
		s.Close()
		delete(d.idleSessions, seq)
	}
	d.mu.Unlock()

	return d.StatelessDialer.Disconnect()
}
