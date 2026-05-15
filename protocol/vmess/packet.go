package vmess

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/pool"
)

func ToAddrPort(addr net.Addr) (netip.AddrPort, error) {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.AddrPort(), nil
	case *net.TCPAddr:
		return v.AddrPort(), nil
	default:
		return netip.ParseAddrPort(addr.String())
	}
}

func (c *Conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, ap, err := c.ReadFromAddrPort(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(ap), nil
}

func (c *Conn) ReadFromAddrPort(p []byte) (n int, addr netip.AddrPort, err error) {
	buf := pool.GetBuffer(MaxUDPSize)
	defer pool.PutBuffer(buf)
	n, err = c.read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if c.metadata.IsPacketAddr() {
		addrTyp, address, err := ExtractPacketAddr(buf)
		addrLen := PacketAddrLength(addrTyp)
		if n < addrLen {
			return 0, netip.AddrPort{}, fmt.Errorf("not enough data to read for PacketAddr")
		}
		copy(p, buf[addrLen:n])
		return n - addrLen, address, err
	} else {
		if !c.dialTgtAddrPort.IsValid() {
			tgt, err := common.ResolveUDPAddr(c.dialTgt)
			if err != nil {
				return 0, netip.AddrPort{}, err
			}
			c.dialTgtAddrPort = tgt.AddrPort()
		}
		copy(p, buf[:n])
		return n, c.dialTgtAddrPort, err
	}
}

func (c *Conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ap, aErr := ToAddrPort(addr)
	if aErr != nil {
		return 0, aErr
	}
	return c.WriteToAddrPort(p, ap)
}

func (c *Conn) WriteToAddrPort(p []byte, ap netip.AddrPort) (n int, err error) {
	if c.metadata.IsPacketAddr() {
		packetAddrLen := AddrPortToPacketAddrLength(ap)
		buf := pool.GetBuffer(packetAddrLen + len(p))
		defer pool.PutBuffer(buf)

		PutPacketAddrFromAddrPort(buf, ap)
		copy(buf[packetAddrLen:], p)
		return c.write(buf)
	}

	return c.write(p)
}
