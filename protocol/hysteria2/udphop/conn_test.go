package udphop

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestRecvQueueValueSendIsAllocFree pins the performance contract of
// recvQueue: packets travel by value through the buffered channel so the
// receive path allocates nothing. A pointer channel would put one 64B
// udpPacket on the heap per received packet — measured at ~680 allocs/s and
// 34% of the process's total alloc_space in production.
func TestRecvQueueValueSendIsAllocFree(t *testing.T) {
	ch := make(chan udpPacket, packetQueueSize)
	buf := make([]byte, udpBufferSize)
	allocs := testing.AllocsPerRun(1000, func() {
		ch <- udpPacket{buf, udpBufferSize, nil, netip.AddrPort{}, nil}
		p := <-ch
		if p.N != udpBufferSize {
			t.Fatal("bad packet")
		}
	})
	if allocs != 0 {
		t.Fatalf("recv path allocates %v objects per packet, want 0", allocs)
	}
}

// The conn must satisfy the full AddrPort-flavored PacketConn shape
// (dae's PacketConnAddrPort), not just the read half.
var _ interface {
	ReadFromAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToAddrPort([]byte, netip.AddrPort) (int, error)
} = (*udpHopPacketConn)(nil)

// TestReadFromAddrPort drives a real loopback UDP socket pair through the
// PacketConn: the packet payload and the remote's AddrPort (as resolved once
// per recvLoop from the connected socket) must both come back intact.
func TestReadFromAddrPort(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverAddr := server.LocalAddr().(*net.UDPAddr)

	client, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatal(err)
	}

	hopAddr, err := ResolveUDPHopAddr(serverAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	hConn, err := NewUDPHopPacketConn(hopAddr, 5*time.Second,
		func(net.Addr) (net.Conn, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer hConn.Close()
	hConn.SetReadDeadline(time.Now().Add(3 * time.Second))

	if _, err := server.WriteToUDP([]byte("hello"), client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	apc, ok := hConn.(interface {
		ReadFromAddrPort([]byte) (int, netip.AddrPort, error)
		WriteToAddrPort([]byte, netip.AddrPort) (int, error)
	})
	if !ok {
		t.Fatal("udpHopPacketConn must implement ReadFromAddrPort/WriteToAddrPort")
	}
	buf := make([]byte, udpBufferSize)
	n, ap, err := apc.ReadFromAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("payload = %q, want %q", buf[:n], "hello")
	}
	if ap != serverAddr.AddrPort() {
		t.Fatalf("addr = %v, want %v", ap, serverAddr.AddrPort())
	}
	if !ap.IsValid() {
		t.Fatal("invalid AddrPort would break quic-go's fast path (double read)")
	}

	// ReadFrom must keep working off the same queue.
	if _, err := server.WriteToUDP([]byte("world"), client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	n, addr, err := hConn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "world" {
		t.Fatalf("payload = %q, want %q", buf[:n], "world")
	}
	if addr == nil {
		t.Fatal("ReadFrom returned nil addr")
	}

	// WriteToAddrPort ignores the addr and writes to the connected peer.
	if _, err := apc.WriteToAddrPort([]byte("ping"), netip.AddrPort{}); err != nil {
		t.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(3 * time.Second))
	rbuf := make([]byte, 32)
	rn, _, err := server.ReadFromUDP(rbuf)
	if err != nil {
		t.Fatal(err)
	}
	if string(rbuf[:rn]) != "ping" {
		t.Fatalf("payload = %q, want %q", rbuf[:rn], "ping")
	}
}

// TestHopNowRerollsPort pins the on-demand hop: a caller that just saw a
// failure can move the connection to another port of the range immediately,
// without waiting for the periodic hop interval. The QUIC connection above the
// packet conn is untouched, so no handshake is lost.
func TestHopNowRerollsPort(t *testing.T) {
	hopAddr, err := ResolveUDPHopAddr("127.0.0.1:10000-10007")
	if err != nil {
		t.Fatal(err)
	}
	var dialed []string
	dialFunc := func(addr net.Addr) (net.Conn, error) {
		u := addr.(*net.UDPAddr)
		dialed = append(dialed, addr.String())
		// A real socket per hop: the hop keeps the previous conn open to
		// receive stragglers, so the old one must not be the same object.
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: u.Port})
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	// A long interval: the only hop that may happen is the on-demand one.
	hConn, err := NewUDPHopPacketConn(hopAddr, time.Hour, dialFunc)
	if err != nil {
		t.Fatal(err)
	}
	defer hConn.Close()
	if len(dialed) != 1 {
		t.Fatalf("initial dials = %d, want 1 (%v)", len(dialed), dialed)
	}

	hopper, ok := hConn.(interface{ HopNow() bool })
	if !ok {
		t.Fatal("udpHopPacketConn must expose HopNow")
	}
	if !hopper.HopNow() {
		t.Fatal("a port-hopping conn must report that it hopped")
	}
	if len(dialed) != 2 {
		t.Fatalf("dials after HopNow = %d, want 2 (%v)", len(dialed), dialed)
	}
	for _, d := range dialed {
		ap, err := netip.ParseAddrPort(d)
		if err != nil {
			t.Fatalf("dialed %q: %v", d, err)
		}
		if ap.Port() < 10000 || ap.Port() > 10007 {
			t.Fatalf("dialed %q outside the hop range", d)
		}
	}
}

// The hop trigger is reached through the net.PacketConn the client holds.
var _ interface{ HopNow() bool } = (*udpHopPacketConn)(nil)
