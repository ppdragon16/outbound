package smux

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
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

const (
	// defaultMaxDialing bounds concurrent in-flight dials when MaxDialing is 0.
	defaultMaxDialing = 4
	// spareDialTimeout bounds a background spare dial so replenish never hangs.
	spareDialTimeout = 10 * time.Second
)

// pooledSession pairs an smux session with the dialer's pool bookkeeping.
// reserved counts streams handed out by getSession but not yet opened via
// OpenStream — it closes the race where a burst of concurrent DialContext calls
// all see NumStreams() below Concurrency before any of them opens a stream,
// piling far more than Concurrency streams onto one session. spare marks an idle
// session the dialer keeps warm for the next connection.
type pooledSession struct {
	*smuxcore.Session
	reserved int
	spare    bool
}

type Smux struct {
	Dialer         netproxy.Dialer
	PassthroughUdp bool

	// Concurrency is the max number of streams per session. 0 means unlimited.
	Concurrency int

	// IdleTimeout is the duration a session stays alive after its last stream
	// closes. 0 means sessions live forever.
	IdleTimeout time.Duration

	// MinSpare is the target number of idle (0-stream) sessions kept warm in
	// the background, so a burst of new connections can grab a session without
	// waiting for a dial. 0 disables pre-warming.
	MinSpare int

	// MaxDialing bounds the number of concurrent in-flight dials. 0 uses a
	// sensible default. Concurrent dials let a connection burst spin up several
	// sessions in parallel instead of serially.
	MaxDialing int

	mu       sync.Mutex
	sessions []*pooledSession

	dialing int
	// dialCond broadcasts "a dial slot freed" to every goroutine waiting in
	// getSession. sync.Cond.Broadcast wakes the whole waiting set without
	// allocating a fresh channel on every dial completion.
	dialCond *sync.Cond
	// closed is set once by Disconnect. It makes in-flight dials, the replenisher,
	// and getSession callers drop their work instead of re-populating the pool
	// after shutdown.
	closed       atomic.Bool
	replenishing atomic.Bool

	idleTimers sync.Map // *pooledSession → *time.Timer
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
	s.closed.Store(false)
	// Pre-warm spare sessions in the background.
	s.maybeReplenish()
	return nil
}

func (s *Smux) Disconnect() error {
	s.closed.Store(true)
	s.mu.Lock()
	for _, ps := range s.sessions {
		ps.Close()
	}
	s.sessions = nil
	// Wake any waiter parked in getSession so it observes closed and returns.
	if s.dialCond != nil {
		s.dialCond.Broadcast()
	}
	s.mu.Unlock()
	return nil
}

func (s *Smux) Alive() bool {
	return s.Dialer.Alive()
}

func (s *Smux) maxDialing() int {
	if s.MaxDialing > 0 {
		return s.MaxDialing
	}
	return defaultMaxDialing
}

// getSession returns an available session from the pool, or creates a new one.
// It never holds s.mu while dialing, so a connection burst can establish
// several sessions in parallel (bounded by maxDialing) instead of serially
// behind a single slow handshake.
func (s *Smux) getSession(ctx context.Context) (*pooledSession, error) {
	for {
		s.mu.Lock()
		if s.closed.Load() {
			s.mu.Unlock()
			return nil, net.ErrClosed
		}
		if s.dialCond == nil {
			s.dialCond = sync.NewCond(&s.mu)
		}
		// Prune dead/full sessions and find the first usable one in a single
		// pass. Assign the pruned slice only after the full scan — assigning it
		// mid-loop would drop the not-yet-scanned live sessions.
		var chosen *pooledSession
		alive := s.sessions[:0]
		for _, ps := range s.sessions {
			if ps.IsClosed() || ps.IsStreamIDFull() {
				continue
			}
			alive = append(alive, ps)
			if chosen == nil && (s.Concurrency <= 0 || ps.NumStreams()+ps.reserved < s.Concurrency) {
				chosen = ps
			}
		}
		s.sessions = alive
		if chosen != nil {
			chosen.spare = false
			chosen.reserved++
			s.mu.Unlock()
			s.maybeReplenish()
			return chosen, nil
		}

		// No reusable session — dial a new one outside s.mu.
		if s.dialing < s.maxDialing() {
			s.dialing++
			s.mu.Unlock()

			ps, err := s.dialSession(ctx)

			s.mu.Lock()
			s.dialing--
			if err == nil {
				if s.closed.Load() {
					// Dialer closed during the dial — drop the session instead
					// of re-populating the pool after shutdown.
					s.mu.Unlock()
					ps.Close()
					return nil, net.ErrClosed
				}
				// Reserve and register atomically so a concurrent fast path
				// can't pick this session before its reservation is visible.
				ps.reserved++
				s.sessions = append(s.sessions, ps)
			}
			s.dialCond.Broadcast()
			s.mu.Unlock()
			if err != nil {
				// Another goroutine may have dialed one in the meantime.
				continue
			}
			s.maybeReplenish()
			return ps, nil
		}

		// Dial concurrency exhausted — wait for a dial to free a slot. The wait
		// happens under s.mu (dialCond.Wait releases it while blocked and
		// re-acquires it on wake), so the slot check and the wait are atomic.
		if ctx.Err() != nil {
			s.mu.Unlock()
			return nil, ctx.Err()
		}
		s.dialCond.Wait()
		s.mu.Unlock()
	}
}

// dialSession dials a fresh underlying connection, performs the smux handshake,
// and returns the wrapped session WITHOUT registering it in the pool. The caller
// registers it atomically with its reservation (getSession) or as a spare
// (replenish), so a session is never visible to a concurrent fast path before
// its reserved count is set.
func (s *Smux) dialSession(ctx context.Context) (*pooledSession, error) {
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

	// KeepAliveTimeout must be 0 here: an smux v1 peer never replies to NOP
	// and sing-box sends nothing on an idle session, so the default 30s
	// "no frame received → close" check reaps healthy idle sessions. With
	// MinSpare pre-warm that turned into a ~15 dials/min re-dial loop in
	// production. The 10s NOP stays on as a write-error liveness probe and
	// NAT refresh; a real peer close still arrives as FIN/RST via recvLoop.
	cfg := *smuxcore.DefaultConfig
	cfg.KeepAliveTimeout = 0
	session, err := smuxcore.Client(conn, &cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}

	ps := &pooledSession{Session: session}
	ps.OnIdle = s.onIdle(ps)
	return ps, nil
}

// onIdle returns the OnIdle callback for a session. The smux core invokes
// OnIdle while holding the session's streamLock, so the pool work is offloaded
// to a goroutine: getSession holds s.mu while calling NumStreams (which takes
// streamLock), and touching s.mu here would invert that lock order and deadlock.
func (s *Smux) onIdle(ps *pooledSession) func() {
	return func() {
		s.cancelIdleTimer(ps)
		go s.handleIdle(ps)
	}
}

// handleIdle recycles a session that just became idle: it becomes a spare if the
// spare pool has room, otherwise IdleTimeout reclaims it.
func (s *Smux) handleIdle(ps *pooledSession) {
	s.mu.Lock()
	if ps.IsClosed() || ps.NumStreams() > 0 || ps.reserved > 0 {
		// Re-used, closed, or reserved for an in-flight OpenStream before we got
		// here — it is not actually idle yet.
		s.mu.Unlock()
		return
	}
	if s.findSession(ps) < 0 {
		// Taken out of the pool earlier (an OpenStream error, or pruned by the
		// getSession scan) but its residual streams were still draining. They are
		// now gone, so close it instead of recycling a session that is no longer
		// in the pool.
		s.mu.Unlock()
		ps.Close()
		return
	}
	if s.MinSpare > 0 && s.countSpareLocked() < s.MinSpare {
		ps.spare = true
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	// Spare pool full or pre-warming disabled: let IdleTimeout reclaim it.
	if s.IdleTimeout > 0 {
		timer := time.AfterFunc(s.IdleTimeout, func() {
			s.idleTimers.Delete(ps)
			s.mu.Lock()
			if ps.IsClosed() || ps.NumStreams() > 0 || ps.reserved > 0 {
				// Still in use, or reserved for a stream about to open.
				s.mu.Unlock()
				return
			}
			s.removeSessionLocked(ps)
			s.mu.Unlock()
			ps.Close()
		})
		s.idleTimers.Store(ps, timer)
	}
}

// countSpareLocked returns the number of live spare sessions. Caller must hold
// s.mu.
func (s *Smux) countSpareLocked() int {
	n := 0
	for _, ps := range s.sessions {
		if ps.spare && !ps.IsClosed() {
			n++
		}
	}
	return n
}

// findSession returns the index of ps in sessions, or -1 if absent. Caller must
// hold s.mu. sessions is small, so the linear scan is cheap and it reads the
// authoritative membership directly instead of maintaining a separate flag.
func (s *Smux) findSession(ps *pooledSession) int {
	for i, se := range s.sessions {
		if se == ps {
			return i
		}
	}
	return -1
}

// maybeReplenish spawns a background replenish loop when the spare pool is below
// target. It is single-flighted so concurrent callers share one replenisher.
func (s *Smux) maybeReplenish() {
	if s.MinSpare <= 0 {
		return
	}
	s.mu.Lock()
	need := s.countSpareLocked() < s.MinSpare
	s.mu.Unlock()
	if need && s.replenishing.CompareAndSwap(false, true) {
		go s.replenish()
	}
}

// replenish dials spare sessions in the background until the spare pool reaches
// MinSpare, or a dial fails. It stops early if the pool fills up concurrently.
func (s *Smux) replenish() {
	defer s.replenishing.Store(false)
	for {
		if s.closed.Load() {
			return
		}
		s.mu.Lock()
		if s.countSpareLocked() >= s.MinSpare {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), spareDialTimeout)
		ps, err := s.dialSession(ctx)
		cancel()
		if err != nil {
			return
		}

		s.mu.Lock()
		if s.closed.Load() {
			// Dialer closed during the dial — drop the session.
			s.mu.Unlock()
			ps.Close()
			return
		}
		if s.countSpareLocked() < s.MinSpare {
			ps.spare = true
			s.sessions = append(s.sessions, ps)
			s.mu.Unlock()
		} else {
			// Pool filled while we were dialing — drop the redundant session.
			s.mu.Unlock()
			ps.Close()
			return
		}
	}
}

// releaseReservation decrements the reserved-stream count for a session after
// OpenStream succeeds, so the reservation tracked in getSession is retired and
// the opened stream is now reflected in NumStreams.
func (s *Smux) releaseReservation(ps *pooledSession) {
	s.mu.Lock()
	if ps.reserved > 0 {
		ps.reserved--
	}
	s.mu.Unlock()
}

// removeSession removes a session from the active pool.
// The session is expected to close itself via notifyReadError/notifyWriteError.
func (s *Smux) removeSession(ps *pooledSession) {
	s.mu.Lock()
	s.removeSessionLocked(ps)
	s.mu.Unlock()
}

// removeSessionLocked removes a session from the pool. Caller must hold s.mu.
func (s *Smux) removeSessionLocked(ps *pooledSession) {
	if i := s.findSession(ps); i >= 0 {
		s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
	}
}

// failOpenStream handles a failed OpenStream: the session leaves the pool and
// its reservation is retired. Retiring the reservation matters — handleIdle
// skips sessions with reserved>0 forever, so leaking it would keep the removed
// session (conn + recvLoop/keepalive goroutines) alive indefinitely.
// A session that never registered a stream (e.g. the SYN write timed out while
// the link stayed up) never triggers OnIdle, so nothing else would close it —
// do it here when it is demonstrably empty.
func (s *Smux) failOpenStream(ps *pooledSession) {
	s.removeSession(ps)
	s.releaseReservation(ps)
	if ps.NumStreams() == 0 {
		ps.Close()
	}
}

// cancelIdleTimer stops the pending idle timeout for a session, if any.
func (s *Smux) cancelIdleTimer(ps *pooledSession) {
	if timer, ok := s.idleTimers.LoadAndDelete(ps); ok {
		timer.(*time.Timer).Stop()
	}
}

func (s *Smux) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		ps, err := s.getSession(ctx)
		if err != nil {
			return nil, err
		}
		s.cancelIdleTimer(ps)
		stream, err := ps.OpenStream()
		if err != nil {
			s.failOpenStream(ps)
			return nil, err
		}
		s.releaseReservation(ps)
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
	ps, err := s.getSession(ctx)
	if err != nil {
		return nil, err
	}
	s.cancelIdleTimer(ps)
	stream, err := ps.OpenStream()
	if err != nil {
		s.failOpenStream(ps)
		return nil, err
	}
	s.releaseReservation(ps)
	return &UDPConn{Conn: Conn{Conn: stream, addr: addr, udp: true, packetAddr: true}}, nil
}
