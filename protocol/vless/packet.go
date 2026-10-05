package vless

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
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

	// The prefix buffer must come from the pool: bLen flows into the
	// io.Reader interface call, so a stack array would escape and turn this
	// into a per-datagram malloc.
	bLen := pool.GetBuffer(2)
	defer pool.PutBuffer(bLen)
	if _, err = io.ReadFull(&c.readWrapper, bLen); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := int(binary.BigEndian.Uint16(bLen))
	if len(p) < length {
		// Drain the oversized datagram so its tail cannot be mistaken for
		// the next packet.
		if _, discardErr := io.CopyN(io.Discard, &c.readWrapper, int64(length)); discardErr != nil {
			return 0, netip.AddrPort{}, discardErr
		}
		return 0, netip.AddrPort{}, netproxy.DatagramDropped(io.ErrShortBuffer)
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
	// Coalesce the 2-byte length prefix and the payload into one pooled
	// buffer and one Write: the previous two-write shape produced two
	// downstream TLS records / smux frames and two syscalls per datagram.
	// (A stack array for the prefix alone does NOT work: c.write is
	// non-inlinable, so the slice escapes and every call would malloc.)
	buf := pool.GetBuffer(2 + len(p))
	defer pool.PutBuffer(buf)
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[2:], p)
	// Return the payload bytes actually carried by the successful write,
	// not a recomputed len(p): c.write promises full-write-or-error today,
	// and deriving it from n keeps that contract honest if the underlying
	// writer ever changes.
	if n, err = c.write(buf[:2+len(p)]); err != nil {
		return 0, err
	}
	return n - 2, nil
}
