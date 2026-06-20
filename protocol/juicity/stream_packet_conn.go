package juicity

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

type PacketConn struct {
	*Conn
	domainIpMapping sync.Map
}

func (c *PacketConn) Write(b []byte) (int, error) {
	ip, err := netip.ParseAddr(c.Conn.Metadata.Hostname)
	if err != nil {
		// Fallback for domain names: use WriteTo with string addr
		return c.WriteTo(b, &net.UDPAddr{
			IP:   net.ParseIP(c.Conn.Metadata.Hostname),
			Port: int(c.Conn.Metadata.Port),
		})
	}
	return c.WriteToAddrPort(b, netip.AddrPortFrom(ip, c.Conn.Metadata.Port))
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

// ReadFrom implements net.PacketConn. Thin wrapper around ReadFromAddrPort.
func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, ap, err := c.ReadFromAddrPort(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(ap), nil
}

// WriteTo implements net.PacketConn. Thin wrapper around WriteToAddrPort.
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ap, err := ToAddrPort(addr)
	if err != nil {
		return 0, err
	}
	return c.WriteToAddrPort(p, ap)
}

// ReadFromAddrPort reads a packet and returns the source address as netip.AddrPort.
func (c *PacketConn) ReadFromAddrPort(p []byte) (n int, ap netip.AddrPort, err error) {
	m := Metadata{}
	if _, err = m.Unpack(c.Conn); err != nil {
		return 0, netip.AddrPort{}, err
	}
	ap, err = m.DomainIpMapping(&c.domainIpMapping)
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("ReadFrom AddrPort: %w", err)
	}

	buf := pool.GetBuffer(2)
	defer pool.PutBuffer(buf)
	if _, err = io.ReadFull(c.Conn, buf[:2]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := int(binary.BigEndian.Uint16(buf))
	if length <= len(p) {
		if n, err = io.ReadFull(c.Conn, p[:length]); err != nil {
			return 0, netip.AddrPort{}, err
		}
		return n, ap, nil
	} else {
		if n, err = io.ReadFull(c.Conn, p); err != nil {
			return 0, netip.AddrPort{}, err
		}
		_, _ = io.CopyN(io.Discard, c.Conn, int64(length-len(p)))
		return n, ap, nil
	}
}

// WriteToAddrPort writes a packet to the given netip.AddrPort.
func (c *PacketConn) WriteToAddrPort(p []byte, ap netip.AddrPort) (n int, err error) {
	metadata := Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeIPv4,
			Hostname: ap.Addr().String(),
			Port:     ap.Port(),
			IsClient: true,
		},
		Network: "udp",
	}
	if ap.Addr().Is6() {
		metadata.Type = protocol.MetadataTypeIPv6
	}
	buf := pool.GetBuffer(metadata.Len() + 2 + len(p))
	defer pool.PutBuffer(buf)
	SealUDP(metadata, buf, p)
	_, err = c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *PacketConn) Close() error {
	return c.Conn.Close()
}

// LocalAddr implements net.PacketConn.
func (c *PacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// SetDeadline implements net.PacketConn.
func (c *PacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline implements net.PacketConn.
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn.
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func SealUDP(metadata Metadata, dst []byte, data []byte) []byte {
	n := metadata.Len()
	// copy first to allow overlap
	copy(dst[n+2:], data)
	metadata.PackTo(dst)
	binary.BigEndian.PutUint16(dst[n:], uint16(len(data)))
	return dst[:n+2+len(data)]
}
