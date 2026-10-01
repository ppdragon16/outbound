package udphop

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRecvQueueValueSendIsAllocFree pins the performance contract of
// recvQueue: packets travel by value through the buffered channel so the
// receive path allocates nothing. A pointer channel would put one 64B
// udpPacket on the heap per received packet — measured at ~680 allocs/s and
// 34% of the process's total alloc_space in production.
func TestRecvQueueValueSendIsAllocFree(t *testing.T) {
	ch := make(chan udpPacket, packetQueueSize)
	buf := make([]byte, udpBufferSize)
	allocs := testing.AllocsPerRun(1000, func() {
		ch <- udpPacket{buf, udpBufferSize, nil, netip.AddrPort{}, nil}
		p := <-ch
		if p.N != udpBufferSize {
			t.Fatal("bad packet")
		}
	})
	if allocs != 0 {
		t.Fatalf("recv path allocates %v objects per packet, want 0", allocs)
	}
}

// The conn must satisfy the full AddrPort-flavored PacketConn shape
// (dae's PacketConnAddrPort), not just the read half.
var _ interface {
	ReadFromAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToAddrPort([]byte, netip.AddrPort) (int, error)
} = (*udpHopPacketConn)(nil)

// TestReadFromAddrPort drives a real loopback UDP socket pair through the
// PacketConn: the packet payload and the remote's AddrPort (as resolved once
// per recvLoop from the connected socket) must both come back intact.
func TestReadFromAddrPort(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverAddr := server.LocalAddr().(*net.UDPAddr)

	client, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatal(err)
	}

	hopAddr, err := ResolveUDPHopAddr(serverAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	hConn, err := NewUDPHopPacketConn(hopAddr, 5*time.Second,
		func(net.Addr) (net.Conn, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer hConn.Close()
	hConn.SetReadDeadline(time.Now().Add(3 * time.Second))

	if _, err := server.WriteToUDP([]byte("hello"), client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	apc, ok := hConn.(interface {
		ReadFromAddrPort([]byte) (int, netip.AddrPort, error)
		WriteToAddrPort([]byte, netip.AddrPort) (int, error)
	})
	if !ok {
		t.Fatal("udpHopPacketConn must implement ReadFromAddrPort/WriteToAddrPort")
	}
	buf := make([]byte, udpBufferSize)
	n, ap, err := apc.ReadFromAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("payload = %q, want %q", buf[:n], "hello")
	}
	if ap != serverAddr.AddrPort() {
		t.Fatalf("addr = %v, want %v", ap, serverAddr.AddrPort())
	}
	if !ap.IsValid() {
		t.Fatal("invalid AddrPort would break quic-go's fast path (double read)")
	}

	// ReadFrom must keep working off the same queue.
	if _, err := server.WriteToUDP([]byte("world"), client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	n, addr, err := hConn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "world" {
		t.Fatalf("payload = %q, want %q", buf[:n], "world")
	}
	if addr == nil {
		t.Fatal("ReadFrom returned nil addr")
	}

	// WriteToAddrPort ignores the addr and writes to the connected peer.
	if _, err := apc.WriteToAddrPort([]byte("ping"), netip.AddrPort{}); err != nil {
		t.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(3 * time.Second))
	rbuf := make([]byte, 32)
	rn, _, err := server.ReadFromUDP(rbuf)
	if err != nil {
		t.Fatal(err)
	}
	if string(rbuf[:rn]) != "ping" {
		t.Fatalf("payload = %q, want %q", rbuf[:rn], "ping")
	}
}

// TestHopNowRerollsPort pins the on-demand hop: a caller that just saw a
// failure can move the connection to another port of the range immediately,
// without waiting for the periodic hop interval. The QUIC connection above the
// packet conn is untouched, so no handshake is lost.
func TestHopNowRerollsPort(t *testing.T) {
	hopAddr, err := ResolveUDPHopAddr("127.0.0.1:10000-10007")
	if err != nil {
		t.Fatal(err)
	}
	var dialed []string
	dialFunc := func(addr net.Addr) (net.Conn, error) {
		u := addr.(*net.UDPAddr)
		dialed = append(dialed, addr.String())
		// A real socket per hop: the hop keeps the previous conn open to
		// receive stragglers, so the old one must not be the same object.
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: u.Port})
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	// A long interval: the only hop that may happen is the on-demand one.
	hConn, err := NewUDPHopPacketConn(hopAddr, time.Hour, dialFunc)
	if err != nil {
		t.Fatal(err)
	}
	defer hConn.Close()
	if len(dialed) != 1 {
		t.Fatalf("initial dials = %d, want 1 (%v)", len(dialed), dialed)
	}

	hopper, ok := hConn.(interface{ HopNow() bool })
	if !ok {
		t.Fatal("udpHopPacketConn must expose HopNow")
	}
	if !hopper.HopNow() {
		t.Fatal("a port-hopping conn must report that it hopped")
	}
	if len(dialed) != 2 {
		t.Fatalf("dials after HopNow = %d, want 2 (%v)", len(dialed), dialed)
	}
	for _, d := range dialed {
		ap, err := netip.ParseAddrPort(d)
		if err != nil {
			t.Fatalf("dialed %q: %v", d, err)
		}
		if ap.Port() < 10000 || ap.Port() > 10007 {
			t.Fatalf("dialed %q outside the hop range", d)
		}
	}
}

// trackedPacketConn marks Close and counts Write, so a test can tell whether a
// socket a hop installed was ever released and whether a write reached it.
type trackedPacketConn struct {
	net.Conn
	closed atomic.Bool
	writes atomic.Int64
}

func (c *trackedPacketConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *trackedPacketConn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(b)
}

// trackedHopDialer dials a real connected UDP socket per hop and remembers
// every one of them.
type trackedHopDialer struct {
	mu    sync.Mutex
	conns []*trackedPacketConn
	dials atomic.Int64
}

func (d *trackedHopDialer) dial(addr net.Addr) (net.Conn, error) {
	c, err := net.DialUDP("udp", nil, addr.(*net.UDPAddr))
	if err != nil {
		return nil, err
	}
	tc := &trackedPacketConn{Conn: c}
	d.dials.Add(1)
	d.mu.Lock()
	d.conns = append(d.conns, tc)
	d.mu.Unlock()
	return tc, nil
}

func (d *trackedHopDialer) openConns() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	open := 0
	for _, c := range d.conns {
		if !c.closed.Load() {
			open++
		}
	}
	return open
}

func newTrackedHopConn(t *testing.T, ports string) (*udpHopPacketConn, *trackedHopDialer) {
	t.Helper()
	hopAddr, err := ResolveUDPHopAddr(ports)
	if err != nil {
		t.Fatal(err)
	}
	d := &trackedHopDialer{}
	pc, err := NewUDPHopPacketConn(hopAddr, time.Hour, d.dial)
	if err != nil {
		t.Fatal(err)
	}
	return pc.(*udpHopPacketConn), d
}

// TestHopAfterCloseDoesNotDial pins that a hop racing Close cannot install a
// socket nobody will ever release. hop() takes the write lock, and Close
// cancels the ctx before taking it: a hop that was waiting for the lock used
// to dial and publish its socket after Close had already closed the current
// and previous ones, leaking an fd and a recvLoop goroutine for the lifetime
// of the process.
func TestHopAfterCloseDoesNotDial(t *testing.T) {
	hConn, dialer := newTrackedHopConn(t, "127.0.0.1:14000-14007")
	hopper := interface{ HopNow() bool }(hConn)

	if err := hConn.Close(); err != nil {
		t.Fatal(err)
	}
	before := dialer.dials.Load()
	hopper.HopNow()
	if got := dialer.dials.Load(); got != before {
		t.Fatalf("a hop after Close dialed %d socket(s) that nothing would ever close", got-before)
	}
	if open := dialer.openConns(); open != 0 {
		t.Fatalf("%d socket(s) still open after Close", open)
	}
}

// TestHopRacingCloseLeavesNoSocketOpen hammers the hop/Close interleaving: a
// hop that loses the race must not leave a live socket behind.
func TestHopRacingCloseLeavesNoSocketOpen(t *testing.T) {
	for i := range 50 {
		hConn, dialer := newTrackedHopConn(t, "127.0.0.1:14000-14007")
		hopper := interface{ HopNow() bool }(hConn)

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			<-start
			_ = hConn.Close()
		})
		wg.Go(func() {
			<-start
			for range 200 {
				hopper.HopNow()
			}
		})
		close(start)
		wg.Wait()

		if open := dialer.openConns(); open != 0 {
			t.Fatalf("iteration %d: Close raced a hop and left %d socket(s) open", i, open)
		}
	}
}

// TestWriteParkedOnTheLockDoesNotWriteAfterClose pins the ctx check inside
// WriteTo's read lock. WriteTo used to test the ctx before taking the lock, so
// a write that passed the check while Close ran in between landed on the
// just-closed socket and returned the socket's "use of closed network
// connection" instead of the conn's own net.ErrClosed.
func TestWriteParkedOnTheLockDoesNotWriteAfterClose(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	sinkConn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	socket := &trackedPacketConn{Conn: sinkConn}
	hopAddr, err := ResolveUDPHopAddr(sink.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := NewUDPHopPacketConn(hopAddr, time.Hour, func(net.Addr) (net.Conn, error) {
		return socket, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	hConn := raw.(*udpHopPacketConn)
	defer hConn.Close()

	// Hold the write lock so the writer parks on the read lock, then cancel the
	// ctx the way Close does and let it through.
	hConn.connMutex.Lock()
	done := make(chan error, 1)
	go func() {
		_, werr := hConn.WriteTo([]byte("parked"), nil)
		done <- werr
	}()
	time.Sleep(100 * time.Millisecond)
	hConn.cancel()
	hConn.connMutex.Unlock()

	werr := <-done
	if !errors.Is(werr, net.ErrClosed) {
		t.Fatalf("write parked across Close = %v, want net.ErrClosed", werr)
	}
	if writes := socket.writes.Load(); writes != 0 {
		t.Fatalf("write parked across Close reached the socket %d time(s)", writes)
	}
}

// TestZeroHopIntervalDisablesThePeriodicHop pins that an explicit 0 interval
// means "no periodic hop" instead of being clamped to a default, while the
// on-demand HopNow still moves the port. A caller that re-rolls the port from
// its own health checks (the hysteria2 client does, through dae's connectivity
// check) does not have to keep paying for blind periodic hops as well.
func TestZeroHopIntervalDisablesThePeriodicHop(t *testing.T) {
	hopAddr, err := ResolveUDPHopAddr("127.0.0.1:10000-10007")
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int64
	dialFunc := func(addr net.Addr) (net.Conn, error) {
		dials.Add(1)
		u, ok := addr.(*net.UDPAddr)
		if !ok {
			return nil, errors.New("unexpected hop address type")
		}
		return net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: u.Port})
	}

	hConn, err := NewUDPHopPacketConn(hopAddr, 0, dialFunc)
	if err != nil {
		t.Fatal(err)
	}
	defer hConn.Close()
	hop, ok := hConn.(*udpHopPacketConn)
	if !ok {
		t.Fatalf("packet conn type = %T", hConn)
	}
	if hop.HopInterval != 0 {
		t.Fatalf("HopInterval = %v, want 0 (periodic hop disabled)", hop.HopInterval)
	}
	// No periodic hop may run: only the initial dial happened.
	time.Sleep(100 * time.Millisecond)
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1: a periodic hop ran with interval 0", got)
	}
	hopper, ok := hConn.(interface{ HopNow() bool })
	if !ok {
		t.Fatal("udpHopPacketConn must expose HopNow")
	}
	if !hopper.HopNow() {
		t.Fatal("a port-hopping conn must report that it hopped")
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dials = %d, want 2 after an on-demand hop", got)
	}

	// A periodic interval still has to clear the minimum.
	if _, err := NewUDPHopPacketConn(hopAddr, 4*time.Second, dialFunc); err == nil {
		t.Fatal("a 4s periodic hop interval must be rejected")
	}
	pc5, err := NewUDPHopPacketConn(hopAddr, 5*time.Second, dialFunc)
	if err != nil {
		t.Fatalf("a 5s periodic hop interval: %v", err)
	}
	defer pc5.Close()
}

// The hop trigger is reached through the net.PacketConn the client holds.
var _ interface{ HopNow() bool } = (*udpHopPacketConn)(nil)
