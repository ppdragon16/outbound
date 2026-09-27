package juicity

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/quic-go"
)

// fakeStream satisfies just enough of quic.Stream for the UDP send path:
// embedding the interface leaves the unused methods unimplemented (and
// panicking if ever called).
type fakeStream struct {
	quic.Stream

	// entered is closed when the first Write is reached; release gates its
	// return so a write can be held in flight.
	entered chan struct{}
	release chan struct{}
	once    sync.Once

	mu      sync.Mutex
	written int
}

func (f *fakeStream) Write(b []byte) (int, error) {
	f.once.Do(func() { close(f.entered) })
	if f.release != nil {
		<-f.release
	}
	f.mu.Lock()
	f.written += len(b)
	f.mu.Unlock()
	return len(b), nil
}

func (f *fakeStream) SetWriteDeadline(time.Time) error { return nil }

func (f *fakeStream) CancelRead(quic.StreamErrorCode) {}

func (f *fakeStream) Close() error { return nil }

func newScratchTestPacketConn(t *testing.T, s quic.Stream) *PacketConn {
	t.Helper()
	return &PacketConn{Conn: &Conn{
		Stream:    s,
		Metadata:  &Metadata{Metadata: protocol.Metadata{IsClient: true}, Network: "udp"},
		onceWrite: true, // skip the connect header: this exercises the packet path
		localAddr: &net.UDPAddr{},
	}}
}

// The send path must serialize into one association-private buffer instead
// of taking a shared-pool Get/Put per datagram.
func TestScratchIsReusedAndReleased(t *testing.T) {
	stream := &fakeStream{entered: make(chan struct{})}
	pc := newScratchTestPacketConn(t, stream)
	ap := netip.MustParseAddrPort("1.1.1.1:53")
	payload := make([]byte, 64)

	for i := 0; i < 3; i++ {
		if _, err := pc.WriteToAddrPort(payload, ap); err != nil {
			t.Fatalf("WriteToAddrPort: %v", err)
		}
	}
	scratch := pc.writeScratch
	if len(scratch) == 0 {
		t.Fatal("scratch was not allocated")
	}
	if stream.written != 3*(scratchLenFor(payload)) {
		t.Fatalf("stream received %d bytes, want %d", stream.written, 3*scratchLenFor(payload))
	}
	if _, err := pc.WriteToAddrPort(payload, ap); err != nil {
		t.Fatal(err)
	}
	if &pc.writeScratch[0] != &scratch[0] {
		t.Fatal("scratch buffer was replaced between writes; it should be reused")
	}

	if err := pc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if pc.writeScratch != nil {
		t.Fatal("Close did not release the scratch to the pool")
	}
}

// scratchLenFor is the framed length of one datagram (metadata + 2-byte
// length + payload) for an IPv4 target.
func scratchLenFor(payload []byte) int {
	m := Metadata{Metadata: protocol.Metadata{Type: protocol.MetadataTypeIPv4}}
	return m.Len() + 2 + len(payload)
}

// Close must not hand the scratch back to the pool while a writer is still
// serializing into it: the recycled buffer could then be handed to an
// unrelated pooled user and overwritten mid-flight (the same defect class as
// the tuic writeScratch race). Deterministic: the write is parked inside the
// stream Write while holding writeMu, and Close must wait for it.
func TestScratchCloseWaitsForInFlightWrite(t *testing.T) {
	stream := &fakeStream{entered: make(chan struct{}), release: make(chan struct{})}
	pc := newScratchTestPacketConn(t, stream)
	ap := netip.MustParseAddrPort("1.1.1.1:53")

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		_, _ = pc.WriteToAddrPort(make([]byte, 64), ap)
	}()
	select {
	case <-stream.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("write never reached the stream")
	}

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_ = pc.Close()
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while a write was still serializing into the scratch")
	case <-time.After(100 * time.Millisecond):
		// expected: Close is waiting on writeMu
	}
	if pc.writeScratch == nil {
		t.Fatal("scratch was released while a writer still held it")
	}

	close(stream.release)
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
	if pc.writeScratch != nil {
		t.Fatal("Close did not release the scratch")
	}
}
