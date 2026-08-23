package client

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type fakePacketConn struct {
	closed atomic.Bool
}

func (f *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (f *fakePacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (f *fakePacketConn) Close() error                           { f.closed.Store(true); return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (f *fakePacketConn) SetDeadline(time.Time) error            { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error        { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error       { return nil }

func TestRaceDialSingleAddr(t *testing.T) {
	pc := &fakePacketConn{}
	outcome := raceDial(context.Background(), []net.Addr{&net.UDPAddr{}}, func(context.Context, net.Addr) dialOutcome {
		return dialOutcome{pktConn: pc}
	})
	if outcome.err != nil {
		t.Fatalf("unexpected error: %v", outcome.err)
	}
	if outcome.pktConn != net.PacketConn(pc) {
		t.Fatalf("expected the single candidate's pktConn")
	}
	if pc.closed.Load() {
		t.Fatalf("single candidate's pktConn must not be closed")
	}
}

func TestRaceDialAllFail(t *testing.T) {
	boom := errors.New("boom")
	outcome := raceDial(context.Background(), []net.Addr{&net.UDPAddr{}, &net.UDPAddr{}}, func(context.Context, net.Addr) dialOutcome {
		return dialOutcome{err: boom}
	})
	if outcome.err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestRaceDialWinnerKeptLoserTornDown(t *testing.T) {
	a := &fakePacketConn{}
	b := &fakePacketConn{}
	addrs := []net.Addr{&net.UDPAddr{IP: net.IPv4(1, 1, 1, 1)}, &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2)}}
	byIP := map[string]*fakePacketConn{
		"1.1.1.1:0": a,
		"2.2.2.2:0": b,
	}
	outcome := raceDial(context.Background(), addrs, func(_ context.Context, addr net.Addr) dialOutcome {
		return dialOutcome{pktConn: byIP[addr.String()]}
	})
	if outcome.err != nil {
		t.Fatalf("unexpected error: %v", outcome.err)
	}

	winner := outcome.pktConn.(*fakePacketConn)
	var loser *fakePacketConn
	switch winner {
	case a:
		loser = b
	case b:
		loser = a
	default:
		t.Fatalf("winner pktConn is not one of the candidates")
	}
	if winner.closed.Load() {
		t.Fatalf("winner pktConn must not be closed")
	}
	// The loser is torn down asynchronously by the background drain; poll
	// briefly for it rather than asserting immediately.
	deadline := time.Now().Add(2 * time.Second)
	for !loser.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatalf("loser pktConn must be closed (torn down)")
		}
		time.Sleep(time.Millisecond)
	}
}
