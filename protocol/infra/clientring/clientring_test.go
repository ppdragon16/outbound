package clientring

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

var errDial = errors.New("dial error")
var errHold = errors.New("hold on")

type fakeClient struct {
	id int
}

func newTestRing(constructed *atomic.Int32, dialErr func(id int) error) *Ring[*fakeClient] {
	return New(
		func(cb func(n int64)) *fakeClient {
			id := int(constructed.Add(1))
			go cb(int64(id)) // one capability report, like quic-go would
			return &fakeClient{id: id}
		},
		func(*fakeClient, func()) {},
		func(*fakeClient) error { return nil },
		0,
		func(err error) bool { return errors.Is(err, errDial) || errors.Is(err, errHold) },
	)
}

// A failover-class error on an established client walks to the next client;
// when the ring is exhausted a fresh client is constructed and the attempt
// retried on it. (An error on a brand-new client - the ring's first ever
// dial - propagates directly: there is nothing to walk to.)
func TestFailoverWalkAndConstruction(t *testing.T) {
	var constructed atomic.Int32
	var attempts atomic.Int32
	r := newTestRing(&constructed, nil)

	err := r.TryNext(func(node *Node[*fakeClient]) error {
		if attempts.Add(1) == 1 {
			return nil // prime the ring
		}
		return errDial // failover
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("priming attempts = %d, want 1", attempts.Load())
	}

	err = r.TryNext(func(node *Node[*fakeClient]) error {
		if attempts.Add(1) == 2 {
			return errDial // failover
		}
		return nil // fresh client works
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts = %d, want 3 (walk + fresh client)", attempts.Load())
	}
	if constructed.Load() != 2 {
		t.Fatalf("constructed = %d, want 2", constructed.Load())
	}
}

// A non-failover error stops the walk.
func TestNonFailoverErrorStopsWalk(t *testing.T) {
	var constructed atomic.Int32
	r := newTestRing(&constructed, nil)
	attempts := 0
	err := r.TryNext(func(*Node[*fakeClient]) error {
		attempts++
		return errHold
	})
	if !errors.Is(err, errHold) {
		t.Fatalf("err = %v, want errHold", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (no failover on non-failover error)", attempts)
	}
}

// A caller whose context is cancelled while blocked on the ring permit
// (held by an in-flight dial/handshake) returns immediately instead of
// queueing behind it - the whole point of the semaphore refactor.
func TestCtxCancelReturnsWhilePermitHeld(t *testing.T) {
	var constructed atomic.Int32
	r := newTestRing(&constructed, nil)

	release := make(chan struct{})
	blocking := make(chan struct{})
	go func() {
		_ = r.TryNext(func(*Node[*fakeClient]) error {
			close(blocking)
			<-release // simulate a long QUIC handshake holding the permit
			return nil
		})
	}()
	<-blocking

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := r.TryNextContext(ctx, func(*Node[*fakeClient]) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancelled waiter blocked %v", elapsed)
	}
	close(release)
}

// Close is terminal and must not resurrect clients via getNew.
func TestCloseIsTerminal(t *testing.T) {
	var constructed atomic.Int32
	r := newTestRing(&constructed, nil)
	if err := r.TryNext(func(*Node[*fakeClient]) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.TryNext(func(*Node[*fakeClient]) error { return nil }); !errors.Is(err, ErrRingClosed) {
		t.Fatalf("err = %v, want ErrRingClosed", err)
	}
	if r.Len() != 0 {
		t.Fatalf("Len after Close = %d, want 0", r.Len())
	}
}

// passiveRemove (client force-close hook) runs on the client's own
// teardown goroutine while a dial may hold the permit. It must complete
// once the dial releases the permit - a bounded wait, not a deadlock. The
// hook must NOT be invoked synchronously from inside an attempt callback:
// that goroutine holds the permit and would self-deadlock (the same
// constraint as the former mutex ring).
func TestPassiveRemoveDoesNotDeadlock(t *testing.T) {
	var constructed atomic.Int32
	r := newTestRing(&constructed, nil)
	var onClose func()
	r.setOnClose = func(cli *fakeClient, fn func()) { onClose = fn }

	// Dial attempt on another goroutine, parked inside the callback.
	release := make(chan struct{})
	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		_ = r.TryNext(func(*Node[*fakeClient]) error {
			close(release)
			<-time.After(50 * time.Millisecond) // simulate a handshake
			return nil
		})
	}()
	<-release

	// Client force-closes itself from its own goroutine mid-dial.
	removed := make(chan struct{})
	go func() {
		defer close(removed)
		onClose()
	}()
	<-removed

	<-dialDone
	if r.Len() != 0 {
		t.Fatalf("Len = %d, want 0 after passive removal", r.Len())
	}
}
