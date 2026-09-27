package tuic

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go"
)

// fakeQuicConn implements just the pieces ensureFullHandshake needs.
type fakeQuicConn struct {
	quic.Connection

	handshake <-chan struct{}
	ctx       context.Context
	state     quic.ConnectionState
}

func (f *fakeQuicConn) HandshakeComplete() <-chan struct{}    { return f.handshake }
func (f *fakeQuicConn) Context() context.Context              { return f.ctx }
func (f *fakeQuicConn) ConnectionState() quic.ConnectionState { return f.state }

// plainConn models a quic.Connection that never exposed HandshakeComplete
// (a plain Dial result, already past the handshake).
type plainConn struct {
	quic.Connection

	state quic.ConnectionState
}

func (p *plainConn) ConnectionState() quic.ConnectionState { return p.state }

func TestEnsureFullHandshakeAcceptsCompletedHandshake(t *testing.T) {
	done := make(chan struct{})
	close(done)
	conn := &fakeQuicConn{handshake: done, ctx: context.Background()}
	if err := ensureFullHandshake(context.Background(), conn); err != nil {
		t.Fatalf("completed, non-0-RTT handshake rejected: %v", err)
	}
}

// A 0-RTT connection must be refused: authenticating over it makes the
// server answer with CloseWithError(0, "") because the exporter is not the
// value the server derives.
func TestEnsureFullHandshakeRefuses0RTT(t *testing.T) {
	done := make(chan struct{})
	close(done)
	conn := &fakeQuicConn{
		handshake: done,
		ctx:       context.Background(),
		state:     quic.ConnectionState{Used0RTT: true},
	}
	err := ensureFullHandshake(context.Background(), conn)
	if !errors.Is(err, Err0RTTNotUsable) {
		t.Fatalf("err = %v, want Err0RTTNotUsable", err)
	}
}

// A terminated or cancelled handshake must not be treated as usable.
func TestEnsureFullHandshakeGivesUpOnCancelledHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn := &fakeQuicConn{handshake: make(chan struct{}), ctx: context.Background()}
	if err := ensureFullHandshake(ctx, conn); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	connCtx, connCancel := context.WithCancel(context.Background())
	connCancel()
	conn = &fakeQuicConn{handshake: make(chan struct{}), ctx: connCtx}
	if err := ensureFullHandshake(context.Background(), conn); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the connection's own error", err)
	}
}

// A plain Dial result carries no HandshakeComplete method; there the
// handshake is already done, so the check must pass without waiting.
func TestEnsureFullHandshakeSkipsPlainDial(t *testing.T) {
	if err := ensureFullHandshake(context.Background(), &plainConn{}); err != nil {
		t.Fatalf("plain Dial result rejected: %v", err)
	}
	// ...but a plain conn reporting 0-RTT (a future dial path) is still refused.
	err := ensureFullHandshake(context.Background(), &plainConn{state: quic.ConnectionState{Used0RTT: true}})
	if !errors.Is(err, Err0RTTNotUsable) {
		t.Fatalf("err = %v, want Err0RTTNotUsable", err)
	}
}

// The guard must not block forever on a handshake that neither completes nor
// cancels: the caller's context has to be able to end the wait.
func TestEnsureFullHandshakeRespectsDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	conn := &fakeQuicConn{handshake: make(chan struct{}), ctx: context.Background()}
	start := time.Now()
	err := ensureFullHandshake(ctx, conn)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("guard waited %v", elapsed)
	}
}
