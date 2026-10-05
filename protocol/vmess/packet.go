package vmess

import (
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/common"
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
	if c.metadata.IsPacketAddr() {
		// Read straight into the caller's buffer. Staging the datagram
		// through a pooled MaxUDPSize (2048) frame buffer capped every
		// packetaddr datagram at 2048 bytes regardless of the caller's
		// capacity, so larger replies (EDNS0 DNS answers, for example) were
		// silently truncated to 2048 bytes and delivered as if complete.
		n, err = c.read(p)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		if n == 0 {
			return 0, netip.AddrPort{}, fmt.Errorf("not enough data to read for PacketAddr")
		}
		if c.pendingReadRemainder() {
			// The datagram did not fit: drop it whole rather than deliver a
			// truncated payload as a complete datagram, and keep the stream
			// aligned for the next one.
			c.discardReadRemainder()
			return 0, netip.AddrPort{}, netproxy.DatagramDropped(io.ErrShortBuffer)
		}
		addrTyp, address, err := ExtractPacketAddr(p[:n])
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		// ExtractPacketAddr rejects a datagram shorter than its own packet
		// address, so addrLen <= n here. The address is a prefix of the
		// datagram; compacting it out is a forward-overlapping copy, which
		// copy handles correctly.
		addrLen := PacketAddrLength(addrTyp)
		return copy(p, p[addrLen:n]), address, nil
	} else {
		// Fixed-target datagrams are read straight into the caller's buffer
		// for the same reason: the old staging buffer truncated them.
		n, err = c.read(p)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		if c.pendingReadRemainder() {
			c.discardReadRemainder()
			return 0, netip.AddrPort{}, netproxy.DatagramDropped(io.ErrShortBuffer)
		}
		if !c.dialTgtAddrPort.IsValid() {
			tgt, err := common.ResolveUDPAddr(c.dialTgt)
			if err != nil {
				return 0, netip.AddrPort{}, err
			}
			c.dialTgtAddrPort = unmapAddrPort(tgt.AddrPort())
		}
		return n, c.dialTgtAddrPort, nil
	}
}

// pendingReadRemainder reports whether the last read delivered only part of
// the frame it decoded, leaving the tail buffered for the next call. A
// datagram reader must never treat such a partial read as a whole datagram.
func (c *Conn) pendingReadRemainder() bool {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	return c.leftToRead != nil && c.indexToRead < len(c.leftToRead)
}

// discardReadRemainder drops the buffered tail of a datagram that did not fit
// the caller's buffer, so the next read starts at the next datagram.
func (c *Conn) discardReadRemainder() {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if c.leftToRead != nil {
		pool.PutBuffer(c.leftToRead)
		c.leftToRead = nil
	}
	c.indexToRead = 0
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
