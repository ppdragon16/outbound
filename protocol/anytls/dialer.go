package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

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
	tlsConfig    *utls.Config

	sessionCounter atomic.Uint64

	mu           sync.Mutex
	idleSessions map[uint64]*session

	idleSessionCheckInterval time.Duration
	idleSessionTimeout       time.Duration
	minIdleSession           int
	heartbeatInterval        time.Duration

	// replenishing guards the background replenishment goroutine so only
	// one runs at a time.
	replenishing atomic.Bool

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
		proxyAddress: header.ProxyAddress,
		key:          sum[:],
		tlsConfig: &utls.Config{
			ServerName:         header.TlsConfig.ServerName,
			InsecureSkipVerify: header.TlsConfig.InsecureSkipVerify,
			// Only use X25519 for key exchange. The default includes
			// X25519MLKEM768 which triggers expensive ML-KEM-768
			// post-quantum key generation (~1184-byte key share and
			// heavy lattice-based computation). For anytls, TLS is an
			// obfuscation layer; security comes from the anytls key.
			CurvePreferences: []utls.CurveID{utls.X25519},
		},
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

// pickIdleSession returns the idle session with the lowest dial latency from
// the pool, or nil if none are available. The caller owns the returned session
// and must either use it or call Close() on it.
func (d *Dialer) pickIdleSession() *session {
	d.mu.Lock()
	defer d.mu.Unlock()

	// First pass: sweep dead entries.
	for seq, s := range d.idleSessions {
		if s.closed.Load() {
			delete(d.idleSessions, seq)
		}
	}
	if len(d.idleSessions) == 0 {
		return nil
	}

	// Second pass: pick the session with the lowest dial latency.
	var best *session
	var bestSeq uint64
	for seq, s := range d.idleSessions {
		if best == nil || s.dialLatency < best.dialLatency {
			best = s
			bestSeq = seq
		}
	}
	delete(d.idleSessions, bestSeq)
	return best
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
		// Pool just shrunk by one — check if we need to replenish.
		d.maybeReplenish()
		return s, nil
	}

	// No healthy idle session — trigger async replenishment and create
	// one synchronously.
	d.maybeReplenish()
	return d.createSession(ctx)
}

// createSession dials a new TCP+TLS connection to the proxy, performs the
// anytls key exchange, and starts the session's background goroutines.
func (d *Dialer) createSession(ctx context.Context) (*session, error) {
	start := time.Now()
	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, err
	}

	tlsConn := utls.Client(conn, d.tlsConfig)

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
	s.dialLatency = time.Since(start)

	go d.manageSession(s, seq)
	go s.run()
	s.startHeartbeat()

	return s, nil
}

// maybeReplenish triggers async session creation when the idle pool drops
// below half of minIdleSession. Only one replenisher runs at a time;
// subsequent calls while a replenisher is already running are no-ops.
func (d *Dialer) maybeReplenish() {
	if d.minIdleSession <= 0 {
		return
	}
	d.mu.Lock()
	idleCount := len(d.idleSessions)
	d.mu.Unlock()

	if idleCount >= d.minIdleSession/2 {
		return
	}
	if d.replenishing.CompareAndSwap(false, true) {
		go d.replenish()
	}
}

// replenish creates sessions in the background until the idle pool reaches
// minIdleSession, or until a connection fails. It stops early if the dialer
// has been disconnected.
func (d *Dialer) replenish() {
	defer d.replenishing.Store(false)

	for {
		if d.ctx.Err() != nil {
			return
		}

		d.mu.Lock()
		idleCount := len(d.idleSessions)
		d.mu.Unlock()

		if idleCount >= d.minIdleSession {
			return
		}

		// Use a generous timeout so the dial doesn't hang indefinitely;
		// the parent dialer may also impose its own deadline.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		s, err := d.createSession(ctx)
		cancel()
		if err != nil {
			return
		}

		d.mu.Lock()
		// If the dialer was disconnected between createSession and now,
		// close the session instead of leaking it into a dead pool.
		if d.ctx.Err() != nil {
			d.mu.Unlock()
			s.Close()
			return
		}
		s.idleSince = time.Now()
		d.idleSessions[s.seq] = s
		d.mu.Unlock()
	}
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
		// Enough non-expired — close all expired.
		for _, s := range expired {
			delete(d.idleSessions, s.seq)
		}
		d.mu.Unlock()
		for _, s := range expired {
			s.Close()
		}
	} else {
		// Need to keep some expired; protect the lowest-latency ones
		// so the pool skews toward faster connections over time.
		slices.SortFunc(expired, func(a, b *session) int {
			if a.dialLatency < b.dialLatency {
				return -1
			}
			if a.dialLatency > b.dialLatency {
				return 1
			}
			return 0
		})
		n := min(d.minIdleSession-nonExpired, len(expired))
		for i, s := range expired {
			if i < n {
				s.idleSince = time.Now() // protect the fastest
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
