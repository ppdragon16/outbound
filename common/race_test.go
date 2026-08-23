package common

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRaceResult struct {
	closed atomic.Bool
}

func (f *fakeRaceResult) Close() { f.closed.Store(true) }

func TestRaceSingleAddr(t *testing.T) {
	val := &fakeRaceResult{}
	got, err := Race(context.Background(), []net.Addr{&net.UDPAddr{}}, func(context.Context, net.Addr) (*fakeRaceResult, error) {
		return val, nil
	}, func(*fakeRaceResult) {
		val.Close()
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != val {
		t.Fatalf("expected the single candidate's result")
	}
	if val.closed.Load() {
		t.Fatalf("single candidate's result must not be closed")
	}
}

func TestRaceAllFail(t *testing.T) {
	boom := errors.New("boom")
	_, err := Race(context.Background(), []net.Addr{&net.UDPAddr{}, &net.UDPAddr{}}, func(context.Context, net.Addr) (*fakeRaceResult, error) {
		return nil, boom
	}, func(*fakeRaceResult) {})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestRaceWinnerKeptLoserTornDown(t *testing.T) {
	a := &fakeRaceResult{}
	b := &fakeRaceResult{}
	addrs := []net.Addr{&net.UDPAddr{IP: net.IPv4(1, 1, 1, 1)}, &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2)}}
	byIP := map[string]*fakeRaceResult{
		"1.1.1.1:0": a,
		"2.2.2.2:0": b,
	}
	winner, err := Race(context.Background(), addrs, func(_ context.Context, addr net.Addr) (*fakeRaceResult, error) {
		return byIP[addr.String()], nil
	}, func(r *fakeRaceResult) {
		r.Close()
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var loser *fakeRaceResult
	switch winner {
	case a:
		loser = b
	case b:
		loser = a
	default:
		t.Fatalf("winner is not one of the candidates")
	}
	if winner.closed.Load() {
		t.Fatalf("winner must not be closed")
	}
	// The loser is torn down asynchronously; poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for !loser.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatalf("loser must be closed (torn down)")
		}
		time.Sleep(time.Millisecond)
	}
}
