package smux

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// discardServer accepts TCP connections and discards everything, so the smux
// client's writes (SYN frames, keepalives) never block. It never sends data, so
// the client's recvLoop stays parked on read.
func startDiscardServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// countingDialer is a mock netproxy.Dialer that dials a discard server and
// counts how many underlying connections it opened.
type countingDialer struct {
	addr      string
	dialCount atomic.Int32
}

func (m *countingDialer) Alive() bool { return true }
func (m *countingDialer) Connect() error {
	return nil
}
func (m *countingDialer) Disconnect() error { return nil }
func (m *countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	m.dialCount.Add(1)
	var d net.Dialer
	return d.DialContext(ctx, network, m.addr)
}
func (m *countingDialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// TestSmuxDialerConcurrentSpike drives a burst of concurrent DialContext calls
// through a Smux with Concurrency=8 and asserts sessions are reused (dialCount
// far below the connection count) and no dial error occurs. It also exercises
// the close path (stream.Close → OnIdle → handleIdle) concurrently, which is
// the lock-ordering-sensitive path. Run with -race.
func TestSmuxDialerConcurrentSpike(t *testing.T) {
	md := &countingDialer{addr: startDiscardServer(t)}
	s := &Smux{
		Dialer:      md,
		Concurrency: 8,
		IdleTimeout: 30 * time.Second,
		MinSpare:    1,
		MaxDialing:  4,
	}
	if err := s.Connect(); err != nil {
		t.Fatal(err)
	}

	const N = 200
	start := make(chan struct{})   // release all goroutines together
	release := make(chan struct{}) // hold streams open until the spike is counted
	var ready sync.WaitGroup
	ready.Add(N)
	var wg sync.WaitGroup
	var errCount atomic.Int32
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := s.DialContext(ctx, "tcp", "example.com:80")
			if err != nil {
				errCount.Add(1)
				ready.Done()
				return
			}
			ready.Done()
			<-release // hold the stream open so all N are concurrent
			conn.Close()
		}()
	}
	close(start)
	ready.Wait() // all N connections established, streams held open

	if n := errCount.Load(); n > 0 {
		t.Fatalf("got %d dial errors out of %d", n, N)
	}
	d := md.dialCount.Load()
	close(release)
	wg.Wait()

	if d >= N {
		t.Fatalf("expected session reuse, but dialed %d times for %d conns", d, N)
	}
	if min := (N + s.Concurrency - 1) / s.Concurrency; int(d) < min {
		t.Fatalf("dialed %d sessions, want >= %d (no reuse)", d, min)
	}
	t.Logf("dialed %d underlying sessions for %d connections (concurrency=8)", d, N)
}

// TestSmuxSparePreWarm verifies that Connect pre-warms MinSpare idle sessions
// in the background.
func TestSmuxSparePreWarm(t *testing.T) {
	md := &countingDialer{addr: startDiscardServer(t)}
	s := &Smux{
		Dialer:     md,
		MinSpare:   2,
		MaxDialing: 4,
	}
	if err := s.Connect(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		n := s.countSpareLocked()
		s.mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.mu.Lock()
	n := s.countSpareLocked()
	s.mu.Unlock()
	if n < 2 {
		t.Fatalf("expected >=2 spare sessions, got %d", n)
	}
}

// TestSmuxDisconnectStopsDialing verifies that after Disconnect, DialContext
// returns net.ErrClosed instead of re-populating the pool.
func TestSmuxDisconnectStopsDialing(t *testing.T) {
	md := &countingDialer{addr: startDiscardServer(t)}
	s := &Smux{
		Dialer:     md,
		MinSpare:   1,
		MaxDialing: 4,
	}
	if err := s.Connect(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := s.DialContext(ctx, "tcp", "example.com:80")
	cancel()
	if err != nil {
		t.Fatalf("DialContext before Disconnect: %v", err)
	}
	conn.Close()

	if err := s.Disconnect(); err != nil {
		t.Fatal(err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if _, err := s.DialContext(ctx2, "tcp", "example.com:80"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("DialContext after Disconnect = %v, want net.ErrClosed", err)
	}
}

// TestSmuxDisconnectDuringSpike races Disconnect against a concurrent dial burst
// and just asserts no panic and no data race (run with -race). Dial errors are
// expected — the point is the Disconnect-during-dial path must not crash or leak.
func TestSmuxDisconnectDuringSpike(t *testing.T) {
	md := &countingDialer{addr: startDiscardServer(t)}
	s := &Smux{
		Dialer:      md,
		Concurrency: 8,
		MinSpare:    1,
		MaxDialing:  4,
	}
	if err := s.Connect(); err != nil {
		t.Fatal(err)
	}

	const N = 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := s.DialContext(ctx, "tcp", "example.com:80")
			if err != nil {
				return // expected during the Disconnect race
			}
			conn.Close()
		}()
	}
	close(start)
	time.Sleep(time.Millisecond) // let some dials get in flight
	_ = s.Disconnect()
	wg.Wait()
}
