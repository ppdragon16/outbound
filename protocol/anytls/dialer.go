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
	"github.com/daeuniverse/outbound/pkg/coalesce"
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
	sessions     map[uint64]*session // all live sessions (idle + active)
	idleSessions map[uint64]*session // idle pool, a subset of sessions

	idleSessionCheckInterval time.Duration
	idleSessionTimeout       time.Duration
	minIdleSession           int

	// sessionAsConn switches TCP dialing to the session-as-conn fast path
	// (session.newDirectConn): the checked-out session is handed to the
	// caller as a net.Conn and its TCP stream is read inline, without the
	// run() dispatch loop or stream objects. Sessions for this mode are
	// never started with run(), so the two paths cannot share a session.
	// UDP still runs on the classic stream path via a dedicated session
	// that is created lazily and shared by all packet conns of this dialer.
	sessionAsConn bool

	udpMu             sync.Mutex
	udpSession        *session // stream-path session dedicated to UDP (lazy)
	heartbeatInterval time.Duration

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
	sessionAsConn := false
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
		sessionAsConn = f.SessionAsConn
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
		sessions:                 make(map[uint64]*session),
		idleSessions:             make(map[uint64]*session),
		idleSessionCheckInterval: checkInterval,
		idleSessionTimeout:       idleTimeout,
		minIdleSession:           minIdle,
		sessionAsConn:            sessionAsConn,
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
		if d.sessionAsConn {
			return s.newDirectConn(addr)
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
	// UDP always runs on the classic stream path: packet streams rely on
	// the run() dispatch loop for fan-in. In session-as-conn mode the
	// pool sessions have no run loop, so UDP gets a dedicated stream-path
	// session, created lazily and shared by every packet conn (its streams
	// multiplex). It is closed with the dialer; a dead one is replaced on
	// the next call.
	if d.sessionAsConn {
		s, err := d.getStreamSession(ctx)
		if err != nil {
			return nil, err
		}
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return s.newPacketStream(net.JoinHostPort("sp.v2.udp-over-tcp.arpa", port), addr)
	}
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

// getStreamSession returns the dialer's dedicated UDP session, creating it
// (with the run() dispatch loop) if none is alive. It never enters the idle
// pool — manageSession for this session must not return it to the pool, so
// its stream-close notifications are drained instead.
func (d *Dialer) getStreamSession(ctx context.Context) (*session, error) {
	d.udpMu.Lock()
	defer d.udpMu.Unlock()
	if d.udpSession != nil && !d.udpSession.Closed() {
		return d.udpSession, nil
	}
	s, err := d.createSessionWithRun(ctx)
	if err != nil {
		return nil, err
	}
	d.udpSession = s
	return s, nil
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
		// Probe carries its own deadline (overriding any lingering one), so
		// a failure — timeout or not — means the conn genuinely cannot take
		// writes. Drop it and try the next candidate.
		if err := s.Probe(); err != nil {
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
// In session-as-conn mode the dispatch loop (run) is not started: the
// checked-out session's TCP stream is consumed inline by sessionConn.Read.
func (d *Dialer) createSession(ctx context.Context) (*session, error) {
	s, err := d.dialNewSession(ctx)
	if err != nil {
		return nil, err
	}
	d.startSession(s, !d.sessionAsConn)
	return s, nil
}

// createSessionWithRun is createSession with the dispatch loop forced on,
// for the dedicated UDP session in session-as-conn mode. That session never
// returns to the idle pool: its stream-close notifications are drained, so
// closing one packetStream does not hand a run()-backed session to the
// session-as-conn pool.
func (d *Dialer) createSessionWithRun(ctx context.Context) (*session, error) {
	s, err := d.dialNewSession(ctx)
	if err != nil {
		return nil, err
	}
	go func() {
		for range s.closeStreamChan {
		}
		// The chan close means the session is dead. manageSession would
		// drop it from d.sessions here; do the same so a replaced UDP
		// session does not linger in the map.
		d.mu.Lock()
		delete(d.sessions, s.seq)
		d.mu.Unlock()
	}()
	go s.run()
	s.startHeartbeat()
	return s, nil
}

// dialNewSession performs the TCP+TLS dial and the anytls key exchange.
func (d *Dialer) dialNewSession(ctx context.Context) (*session, error) {
	start := time.Now()
	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, err
	}

	// Coalesce the TLS records of one write burst into one socket write;
	// the session drains the coalescer after each framed burst. (Port of
	// koutbound 723da22.)
	co := coalesce.New(conn)
	tlsConn := utls.Client(co, d.tlsConfig)

	buf := pool.GetBuffer(len(d.key) + 2)
	defer pool.PutBuffer(buf)
	copy(buf, d.key)
	binary.BigEndian.PutUint16(buf[len(d.key):], uint16(0))
	if _, err := tlsConn.Write(buf); err != nil {
		tlsConn.Close()
		return nil, err
	}
	// The auth write must leave before the session's first read: drain
	// explicitly rather than relying on the coalescer's read-flush hook.
	if err := co.Flush(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	seq := d.sessionCounter.Add(1)
	s := newSession(tlsConn, seq)
	s.flusher = co
	s.heartbeatInterval = d.heartbeatInterval
	s.idleSince = time.Now()
	s.dialLatency = time.Since(start)

	d.mu.Lock()
	d.sessions[seq] = s
	d.mu.Unlock()

	return s, nil
}

// startSession launches the background goroutines. withRun=false leaves the
// TCP stream unconsumed so a sessionConn can read it inline.
func (d *Dialer) startSession(s *session, withRun bool) {
	go d.manageSession(s, s.seq)
	if withRun {
		go s.run()
	}
	s.startHeartbeat()
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
	delete(d.sessions, seq)
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

	// Collect expired and non-expired sessions under the lock, then release it
	// before the slow work (sorting, closing) so a burst of closes doesn't
	// hold d.mu and starve manageSession / removeStream.
	d.mu.Lock()
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
	d.mu.Unlock()

	if len(expired) == 0 {
		return
	}

	// Decide which expired sessions to keep (protect the lowest-latency ones)
	// when the pool would otherwise fall below minIdleSession.
	var toKeep []*session
	if d.minIdleSession > 0 && nonExpired < d.minIdleSession {
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
		toKeep = expired[:n]
		expired = expired[n:]
	}

	// Remove the closing sessions from the pool and refresh the kept ones'
	// idle timestamps under a brief lock.
	d.mu.Lock()
	for _, s := range expired {
		delete(d.idleSessions, s.seq)
	}
	for _, s := range toKeep {
		s.idleSince = time.Now() // protect the fastest
	}
	d.mu.Unlock()

	// Close outside the lock.
	for _, s := range expired {
		s.Close()
	}
}

// Disconnect shuts down the dialer: stops the cleanup loop, closes all
// idle sessions, and disconnects the parent.
func (d *Dialer) Disconnect() error {
	d.cancel()

	// Close every live session — idle AND active. Closing only idleSessions
	// leaked sessions that still had open streams when the dialer was removed
	// (e.g. via update-sub): AbortConns closes the streams, but the session's
	// idleSessions insertion happens on the manageSession goroutine, so it can
	// race with this loop.
	d.mu.Lock()
	for seq, s := range d.sessions {
		s.Close()
		delete(d.sessions, seq)
	}
	for seq := range d.idleSessions {
		delete(d.idleSessions, seq)
	}
	d.mu.Unlock()

	return d.StatelessDialer.Disconnect()
}
