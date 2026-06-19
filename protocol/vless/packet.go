package vless

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"

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
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	// FIXME: a compromise on Symmetric NAT
	addr = c.cachedProxyAddrIpIP

	bLen := pool.GetBuffer(2)
	defer pool.PutBuffer(bLen)
	if _, err = io.ReadFull(&c.readWrapper, bLen); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := int(binary.BigEndian.Uint16(bLen))
	if len(p) < length {
		return 0, netip.AddrPort{}, fmt.Errorf("buf size is not enough")
	}
	n, err = io.ReadFull(&c.readWrapper, p[:length])
	return n, addr, err
}

func (c *Conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ap, aErr := ToAddrPort(addr)
	if aErr != nil {
		return 0, aErr
	}
	return c.WriteToAddrPort(p, ap)
}

func (c *Conn) WriteToAddrPort(p []byte, _ netip.AddrPort) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	bLen := pool.GetBuffer(2)
	defer pool.PutBuffer(bLen)
	binary.BigEndian.PutUint16(bLen, uint16(len(p)))
	if _, err = c.write(bLen); err != nil {
		return 0, err
	}
	return c.write(p)
}
