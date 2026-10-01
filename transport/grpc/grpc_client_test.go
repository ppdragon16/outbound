package grpc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
)

// TestTunWithinSetupBudgetTimesOut pins the stream-setup budget. The stream is
// the tunnel, so it must outlive the dial (its context cannot carry the dial
// budget); a server that accepts the gRPC transport and then never answers the
// tun setup therefore used to hang DialContext forever — and with it the
// connectivity check that issued it.
func TestTunWithinSetupBudgetTimesOut(t *testing.T) {
	old := grpcStreamSetupTimeout
	grpcStreamSetupTimeout = 200 * time.Millisecond
	t.Cleanup(func() { grpcStreamSetupTimeout = old })

	streamCtx, streamCloser := context.WithCancel(context.Background())
	closerCalled := false
	closer := context.CancelFunc(func() {
		closerCalled = true
		streamCloser()
	})

	done := make(chan error, 1)
	go func() {
		// Never answers; only the stream context ending can release it.
		_, err := tunWithinSetupBudget(streamCtx, closer, func(ctx context.Context) (proto.GunService_TunClient, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("setup reported success although the server never answered")
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("err = %v, want a setup timeout", err)
		}
		if !closerCalled {
			t.Fatal("the stream context must be cancelled so the aborted RPC does not leak")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tun stream setup was not bounded: the dial hung without a deadline")
	}
}

// TestTunWithinSetupBudgetPassesThrough keeps the happy path intact.
func TestTunWithinSetupBudgetPassesThrough(t *testing.T) {
	old := grpcStreamSetupTimeout
	grpcStreamSetupTimeout = time.Second
	t.Cleanup(func() { grpcStreamSetupTimeout = old })

	streamCtx, streamCloser := context.WithCancel(context.Background())
	defer streamCloser()
	closerCalled := false
	sentinel := errors.New("stream")
	tun, err := tunWithinSetupBudget(streamCtx, func() { closerCalled = true }, func(context.Context) (proto.GunService_TunClient, error) {
		return nil, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
	if tun != nil {
		t.Fatal("tun must stay nil on the error path")
	}
	if !closerCalled {
		t.Fatal("a failed setup must release its stream context")
	}
}
