package udphop

import (
	"net"
	"net/netip"
	"testing"

	quic "github.com/daeuniverse/quic-go"
)

// The hop conn must look like a plain PacketConn to quic-go, NOT like an
// OOBCapablePacketConn.
//
// That interface switches quic-go onto a raw-fd fast path which captures one
// syscall.RawConn and marshals one destination address when the transport is
// created. A hop replaces the socket - and therefore the fd - every interval,
// so such a path keeps reading from the retired socket, and it cannot express
// the hop address (a port range) at all: quic-go rejects it with
// "oobConn.WritePacket: address is not a *net.UDPAddr". With the plain path
// every read and write resolves the *current* socket instead.
//
// Re-adding ReadMsgUDP/WriteMsgUDP/SyscallConn to udpHopPacketConn would
// silently break port hopping again, so this assertion is load-bearing.
func TestHopConnIsNotOOBCapable(t *testing.T) {
	var pc net.PacketConn = (*udpHopPacketConn)(nil)
	if _, ok := pc.(quic.OOBCapablePacketConn); ok {
		t.Fatal("udpHopPacketConn must not satisfy quic.OOBCapablePacketConn: its fd changes on every hop")
	}
}

// The plain path still wants the AddrPort-flavored read (quic-go's basicConn
// prefers ReadFromAddrPort) and dae's PacketConnAddrPort uses both.
var _ interface {
	ReadFromAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToAddrPort([]byte, netip.AddrPort) (int, error)
} = (*udpHopPacketConn)(nil)
