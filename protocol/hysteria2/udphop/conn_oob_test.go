package udphop

import (
	"context"
	"net"
	"net/netip"
	"testing"

	quic "github.com/daeuniverse/quic-go"
	"golang.org/x/net/ipv4"
)

// Compile-time checks: udpHopPacketConn must satisfy quic-go's
// OOBCapablePacketConn (else quic.wrapConn silently falls back to basicConn
// and disables recvmmsg/GSO/ECN), and its ReadBatch signature must match
// quic-go's unexported batchConn interface (structural typing) so batched
// reads route through the recvQueue instead of pinning the first hop's fd.
var (
	_ quic.OOBCapablePacketConn = (*udpHopPacketConn)(nil)
	_ interface {
		ReadBatch(ms []ipv4.Message, flags int) (int, error)
	} = (*udpHopPacketConn)(nil)
)

func newTestHopConn() *udpHopPacketConn {
	curConn, err := net.Dial("udp", "127.0.0.1:1")
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &udpHopPacketConn{
		currentConn: curConn,
		recvQueue:   make(chan udpPacket, packetQueueSize),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// ReadBatch must drain queued packets into consecutive ipv4.Message slots,
// recycle their pool buffers, and stop at an empty queue.
func TestReadBatchDrainsQueue(t *testing.T) {
	u := newTestHopConn()
	defer u.currentConn.Close()

	for i := 0; i < 3; i++ {
		buf := make([]byte, 100+i)
		u.recvQueue <- udpPacket{
			Buf:      buf,
			N:        len(buf),
			Addr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
			AddrPort: netip.MustParseAddrPort("127.0.0.1:1"),
		}
	}

	ms := make([]ipv4.Message, 4)
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, 2048)}
	}
	count, err := u.ReadBatch(ms, 0)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("ReadBatch = %d messages, want 3", count)
	}
	for i := 0; i < 3; i++ {
		if ms[i].N != 100+i {
			t.Fatalf("ms[%d].N = %d, want %d", i, ms[i].N, 100+i)
		}
	}
}

// ReadBatch must surface the session-closed state instead of hanging.
func TestReadBatchClosed(t *testing.T) {
	u := newTestHopConn()
	u.cancel()
	if _, err := u.ReadBatch(make([]ipv4.Message, 2), 0); err != net.ErrClosed {
		t.Fatalf("ReadBatch err = %v, want net.ErrClosed", err)
	}
}

// ReadMsgUDP exists for the interface, not for quic-go's read path; it must
// deliver queue contents like ReadFrom.
func TestReadMsgUDPDeliversQueuedPacket(t *testing.T) {
	u := newTestHopConn()
	defer u.currentConn.Close()
	u.recvQueue <- udpPacket{
		Buf:      []byte("hello"),
		N:        5,
		Addr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		AddrPort: netip.MustParseAddrPort("127.0.0.1:1"),
	}
	b := make([]byte, 2048)
	n, _, _, addr, err := u.ReadMsgUDP(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || addr == nil || addr.Port != 1 {
		t.Fatalf("n=%d addr=%v", n, addr)
	}
}
