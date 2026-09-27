package client

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/quic-go"
)

// fakeSendConn satisfies just enough of quic.Connection for the UDP send
// path: embedding the interface leaves the unused methods unimplemented (and
// panicking if ever called), so the test cannot accidentally depend on more
// than SendDatagram.
type fakeSendConn struct {
	quic.Connection

	// entered is closed when the first SendDatagram call is reached;
	// release gates its return so a write can be held in flight.
	entered chan struct{}
	release chan struct{}
	once    sync.Once

	mu   sync.Mutex
	sent int
}

func (f *fakeSendConn) SendDatagram(b []byte) error {
	f.once.Do(func() { close(f.entered) })
	if f.release != nil {
		<-f.release
	}
	f.mu.Lock()
	f.sent++
	f.mu.Unlock()
	return nil
}

func newScratchTestSession(t *testing.T, conn *fakeSendConn) *udpConn {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sm := &udpSessionManager{conn: conn, ctx: ctx, cancel: cancel}
	u := &udpConn{
		ID:        1,
		ReceiveCh: make(chan []byte, 4),
		conn:      conn,
		sm:        sm,
		ctx:       ctx,
		cancel:    cancel,
	}
	sm.connMap.Store(uint32(1), u)
	return u
}

// The send path must serialize into one session-private buffer instead of
// taking a shared-pool Get/Put per datagram.
func TestUDPScratchIsReusedAndReleased(t *testing.T) {
	conn := &fakeSendConn{entered: make(chan struct{})}
	u := newScratchTestSession(t, conn)
	ap := netip.MustParseAddrPort("1.1.1.1:53")
	payload := make([]byte, 64)

	for i := 0; i < 3; i++ {
		if _, err := u.WriteToAddrPort(payload, ap); err != nil {
			t.Fatalf("WriteToAddrPort: %v", err)
		}
	}
	scratch := u.writeScratch
	if len(scratch) < protocol.MaxUDPSize {
		t.Fatalf("scratch len = %d, want >= %d", len(scratch), protocol.MaxUDPSize)
	}
	if conn.sent != 3 {
		t.Fatalf("datagrams sent = %d, want 3", conn.sent)
	}
	if _, err := u.WriteToAddrPort(payload, ap); err != nil {
		t.Fatal(err)
	}
	if &u.writeScratch[0] != &scratch[0] {
		t.Fatal("scratch buffer was replaced between writes; it should be reused")
	}

	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if u.writeScratch != nil {
		t.Fatal("Close did not release the scratch to the pool")
	}
}

// Close must not hand the scratch back to the pool while a writer is still
// serializing into it: the recycled buffer could then be handed to an
// unrelated pooled user and overwritten mid-flight (the same defect class as
// the tuic writeScratch race). This is deterministic rather than -race
// dependent: the write is parked inside SendDatagram holding writeMu, and
// Close must wait for it.
func TestUDPScratchCloseWaitsForInFlightWrite(t *testing.T) {
	conn := &fakeSendConn{entered: make(chan struct{}), release: make(chan struct{})}
	u := newScratchTestSession(t, conn)
	ap := netip.MustParseAddrPort("1.1.1.1:53")

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		_, _ = u.WriteToAddrPort(make([]byte, 64), ap)
	}()
	select {
	case <-conn.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("write never reached SendDatagram")
	}

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_ = u.Close()
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while a write was still serializing into the scratch")
	case <-time.After(100 * time.Millisecond):
		// expected: Close is waiting on writeMu
	}
	if u.writeScratch == nil {
		t.Fatal("scratch was released while a writer still held it")
	}

	close(conn.release)
	select {
	case <-writerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("write did not finish")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after the in-flight write completed")
	}
	if u.writeScratch != nil {
		t.Fatal("Close did not release the scratch")
	}
}
