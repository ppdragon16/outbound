package obfs

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// addrPortInner adds the quic-go fast path onto a real UDP socket, mirroring
// how udpHopPacketConn exposes ReadFromAddrPort.
type addrPortInner struct {
	*net.UDPConn
}

func (c *addrPortInner) ReadFromAddrPort(p []byte) (int, netip.AddrPort, error) {
	return c.UDPConn.ReadFromUDPAddrPort(p)
}

func (c *addrPortInner) WriteToAddrPort(p []byte, ap netip.AddrPort) (int, error) {
	return c.UDPConn.WriteToUDPAddrPort(p, ap)
}

// The wrapper must satisfy the full AddrPort-flavored PacketConn shape.
var _ interface {
	ReadFromAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToAddrPort([]byte, netip.AddrPort) (int, error)
} = (*obfsPacketConnUDP)(nil)

// TestObfsReadFromAddrPort verifies that the wrapper both forwards the fast
// path and deobfuscates the payload, and that the peer address survives.
func TestObfsReadFromAddrPort(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	inner0, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	inner := &addrPortInner{UDPConn: inner0}

	ob, err := newSalamanderObfuscator([]byte("test-psk"))
	if err != nil {
		t.Fatal(err)
	}
	opc, ok := wrapPacketConn(inner, ob).(*obfsPacketConnUDP)
	if !ok {
		t.Fatal("udp-like inner must produce obfsPacketConnUDP")
	}
	defer opc.Close()

	// Craft one obfuscated wire packet and deliver it to the inner socket.
	wire := make([]byte, 128)
	payload := []byte("deobfuscated-payload")
	wireLen := ob.Obfuscate(payload, wire)
	if wireLen != len(payload)+smSaltLen {
		t.Fatalf("Obfuscate = %d", wireLen)
	}
	if _, err := peer.WriteToUDP(wire[:wireLen], inner0.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, udpBufferSize)
	opc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, ap, err := opc.ReadFromAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload = %q, want %q", buf[:n], payload)
	}
	if ap != peerAddr.AddrPort() {
		t.Fatalf("addr = %v, want %v", ap, peerAddr.AddrPort())
	}

	// WriteToAddrPort forwards through the obfuscation layer: the peer must
	// receive an obfuscated wire packet that deobfuscates to the payload.
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := opc.WriteToAddrPort(payload, peerAddr.AddrPort()); err != nil {
		t.Fatal(err)
	}
	wbuf := make([]byte, udpBufferSize)
	rn, _, err := peer.ReadFromUDP(wbuf)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, udpBufferSize)
	if n := ob.Deobfuscate(wbuf[:rn], out); n != len(payload) || string(out[:n]) != string(payload) {
		t.Fatalf("peer payload = %q, want %q", out[:n], payload)
	}
}
