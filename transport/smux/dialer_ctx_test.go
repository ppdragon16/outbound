package smux

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// failingDialer models an unreachable node: every session dial fails at once.
type failingDialer struct{}

func (failingDialer) Alive() bool       { return true }
func (failingDialer) Connect() error    { return nil }
func (failingDialer) Disconnect() error { return nil }
func (failingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("node unreachable")
}
func (failingDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, errors.New("node unreachable")
}

// hangingDialer never completes its dial and deliberately ignores ctx, which is
// what a half-dead peer (TCP accepted, handshake never finishes) looks like.
type hangingDialer struct{ release chan struct{} }

func (h *hangingDialer) Alive() bool       { return true }
func (h *hangingDialer) Connect() error    { return nil }
func (h *hangingDialer) Disconnect() error { return nil }
func (h *hangingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	<-h.release
	return nil, errors.New("released")
}
func (h *hangingDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	<-h.release
	return nil, errors.New("released")
}

func dialWithWatchdog(t *testing.T, s *Smux, ctx context.Context) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := s.DialContext(ctx, "tcp", "example.com:443")
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		return errDialDidNotReturn
	}
}

var errDialDidNotReturn = errors.New("DialContext did not return")

// TestDialContextHonoursContextWhenEverySessionDialFails pins netproxy.Dialer's
// contract — "Must return while the context is cancelled. Otherwise, everything
// will be blocked." — for the retry loop in getSession. Every session dial
// failing (node unreachable) used to loop forever without re-checking ctx, so
// DialContext never returned: the connectivity check that calls it never
// finished (hence no per-network-type log lines and never alive), and any real
// caller hung instead of getting a timeout.
func TestDialContextHonoursContextWhenEverySessionDialFails(t *testing.T) {
	s := &Smux{Dialer: failingDialer{}}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := dialWithWatchdog(t, s, ctx)
	if errors.Is(err, errDialDidNotReturn) {
		t.Fatal("DialContext never returned although every dial failed and the context expired")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext returned %v, want context.DeadlineExceeded", err)
	}
}

// TestDialContextHonoursContextWhileWaitingForADialSlot pins the second wait
// site: with the dial slots occupied by a hung handshake, a waiter parked in
// dialCond.Wait() was only woken by a dial completion (and checked ctx only
// before waiting), so a bounded context could not bound it either.
func TestDialContextHonoursContextWhileWaitingForADialSlot(t *testing.T) {
	h := &hangingDialer{release: make(chan struct{})}
	defer close(h.release)
	s := &Smux{Dialer: h, MaxDialing: 1}

	// Occupy the only dial slot with a dial that never finishes.
	go func() {
		_, _ = s.DialContext(context.Background(), "tcp", "example.com:443")
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		dialing := s.dialing
		s.mu.Unlock()
		if dialing >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := dialWithWatchdog(t, s, ctx)
	if errors.Is(err, errDialDidNotReturn) {
		t.Fatal("DialContext never returned while waiting for a dial slot, although its context expired")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext returned %v, want context.DeadlineExceeded", err)
	}
}
