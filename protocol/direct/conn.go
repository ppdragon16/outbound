package direct

import (
	"net"
	"net/netip"
)

type PacketConn struct {
	*net.UDPConn
}

func (c *PacketConn) ReadFromAddrPort(b []byte) (n int, ap netip.AddrPort, err error) {
	return c.ReadFromUDPAddrPort(b)
}

func (c *PacketConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (int, error) {
	return c.WriteToUDPAddrPort(b, ap)
}
