package direct

import (
	"net"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
)

type PacketConn struct {
	net.PacketConn
	resolver *net.Resolver
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if _, ok := addr.(*netproxy.ProxyAddr); ok {
		addr, err = common.ResolveUDPAddrWithResolver(c.resolver, addr.String())
		if err != nil {
			return
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}
