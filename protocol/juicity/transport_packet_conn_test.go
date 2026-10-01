package juicity

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go"
)

// TestReadFromAddrPortHonoursReadDeadline pins the read deadline contract of
// the juicity packet conn. ReadNonQUICPacket only returns on its context, a
// queued packet, or transport close, and the shared UDP socket's deadline is
// deliberately not armed (the QUIC demultiplexer reads that socket), so with
// context.TODO() a read with no traffic blocked forever — which is how a
// connectivity check's UDP probe could wedge.
func TestReadFromAddrPortHonoursReadDeadline(t *testing.T) {
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer socket.Close()
	tr := &quic.Transport{Conn: socket}
	pc := &TransportPacketConn{
		Transport: tr,
		tgt:       netip.MustParseAddrPort("127.0.0.1:53"),
	}

	if err := pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := pc.ReadFromAddrPort(make([]byte, 1500))
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadFromAddrPort reported success with no traffic")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadFromAddrPort ignored the read deadline (ReadNonQUICPacket was given a context without it)")
	}
}
