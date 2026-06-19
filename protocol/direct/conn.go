package direct

import (
	"net"
	"net/netip"
)

type PacketConn struct {
	net.PacketConn
}

func (c *PacketConn) ReadFromAddrPort(b []byte) (n int, ap netip.AddrPort, err error) {
	return c.PacketConn.(*net.UDPConn).ReadFromUDPAddrPort(b)
}

func (c *PacketConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (int, error) {
	return c.PacketConn.(*net.UDPConn).WriteToUDPAddrPort(b, ap)
}
