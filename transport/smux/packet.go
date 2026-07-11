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
	// Pre-allocated header buffers for ReadFromAddrPort and WriteToAddrPort.
	// They live on the struct instead of the stack so that passing slices of
	// them to io.ReadFull / io.Writer.Write (both interface methods) does NOT
	// cause a heap allocation — the backing arrays are already on the heap
	// because UDPConn itself is always heap-allocated.
	//
	// Separate buffers avoid a data race when a read and write happen
	// concurrently on the same connection (smux streams are bidirectional).
	rdBuf [21]byte
	wrBuf [21]byte
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
	buf := c.rdBuf[:]

	// 1. Read SOCKS5 address (ATYP + IP + PORT) into buf.
	addr, addrBytes, err := socks5.ReadAddrPortBuf(&c.Conn, buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// 2. Read the 2-byte data length that follows the address.
	if _, err = io.ReadFull(&c.Conn, buf[addrBytes:addrBytes+2]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := binary.BigEndian.Uint16(buf[addrBytes:])

	// 3. Read the payload.
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
	headerLen := socks5.PutAddrPortLen(c.wrBuf[:], ap, uint16(len(b)))
	if _, err = c.Conn.Write(c.wrBuf[:headerLen]); err != nil {
		return 0, err
	}
	if _, err = c.Conn.Write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}
