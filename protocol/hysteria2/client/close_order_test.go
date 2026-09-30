package client

import (
	"context"
	"net"
	"slices"
	"sync"
	"testing"

	"github.com/daeuniverse/quic-go"
)

// releaseRecorder records the order in which teardown releases resources.
type releaseRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *releaseRecorder) add(event string) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
}

func (r *releaseRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.events)
}

// releaseOrderPacketConn only ever has Close called on it; the embedded nil
// PacketConn is enough because closeState does nothing else with it.
type releaseOrderPacketConn struct {
	net.PacketConn
	rec *releaseRecorder
}

func (c *releaseOrderPacketConn) Close() error {
	c.rec.add("packetConn")
	return nil
}

type releaseOrderConn struct {
	quic.Connection
	rec *releaseRecorder
}

func (c *releaseOrderConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.rec.add("quicConn")
	return nil
}

// TestCloseReleasesTheQuicConnBeforeItsPacketConn pins the teardown order of
// one tunnel generation.
//
// quic-go writes to the packet conn from its own send loop and turns a write
// error into the connection's close error (sendQueue.Run -> destroyImpl),
// which every later SendDatagram/OpenStream then returns verbatim. A hop conn
// answers net.ErrClosed as soon as its ctx is cancelled, so releasing it while
// the connection is still live poisons the connection with "use of closed
// network connection" — every datagram packed but not yet sent fails with it,
// which is the burst dae reports as "DNS dialSend error". CloseWithError
// returns only after the send loop stopped (sendQueue.Close waits for it), so
// the packet conn must go last.
func TestCloseReleasesTheQuicConnBeforeItsPacketConn(t *testing.T) {
	rec := &releaseRecorder{}
	smCtx, smCancel := context.WithCancel(context.Background())
	c := &Client{
		pktConn: &releaseOrderPacketConn{rec: rec},
		conn:    &releaseOrderConn{rec: rec},
		udpSM: &udpSessionManager{
			ctx:    smCtx,
			cancel: func() { rec.add("udpSM"); smCancel() },
		},
	}

	c.close()

	want := []string{"quicConn", "udpSM", "packetConn"}
	if got := rec.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("teardown order = %v, want %v: the packet conn must be released only after the QUIC connection stopped writing to it", got, want)
	}
	if c.pktConn != nil || c.conn != nil || c.udpSM != nil {
		t.Fatal("close must clear every field of the retired generation")
	}
}
