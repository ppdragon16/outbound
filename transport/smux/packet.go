package smux

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/protocol/socks5"
)

type UDPConn struct {
	Conn
}

func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, ap, err := c.ReadFromAddrPort(b)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(ap), nil
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	ap, err := socks5.ToAddrPort(addr)
	if err != nil {
		return 0, err
	}
	return c.WriteToAddrPort(b, ap)
}

func (c *UDPConn) ReadFromAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	addr, err = socks5.ReadAddrPort(&c.Conn)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	var lengthBuf [2]byte
	if _, err = io.ReadFull(&c.Conn, lengthBuf[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := binary.BigEndian.Uint16(lengthBuf[:])
	if int(length) > len(b) {
		return 0, netip.AddrPort{}, fmt.Errorf("buffer too small: %d < %d", len(b), length)
	}
	n, err = io.ReadFull(&c.Conn, b[:length])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, addr, nil
}

func (c *UDPConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (n int, err error) {
	if len(b) == 0 {
		_, err = c.Conn.Write(nil)
		return 0, err
	}
	// Stack-allocated header: ATYP(1) + IP(4/16) + PORT(2) + LENGTH(2).
	// Two writes are safe because smux is a stream — the receiver reads
	// addr, length, then payload sequentially via ReadFromAddrPort.
	var header [21]byte
	headerLen := socks5.PutAddrPortLen(header[:], ap, uint16(len(b)))
	if _, err = c.Conn.Write(header[:headerLen]); err != nil {
		return 0, err
	}
	if _, err = c.Conn.Write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}
