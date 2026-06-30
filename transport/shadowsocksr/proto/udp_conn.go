package proto

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
	"github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
)

type PacketConn struct {
	shadowsocks_stream.PacketConn
	Protocol IProtocol
	tgt      string
}

func NewPacketConn(c shadowsocks_stream.PacketConn, proto IProtocol, tgt string) (*PacketConn, error) {
	return &PacketConn{
		PacketConn: c,
		Protocol:   proto,
		tgt:        tgt,
	}, nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	return netproxy.NewAddr("udp", c.tgt)
}

func (c *PacketConn) RemoteAddr() net.Addr {
	return netproxy.NewAddr("udp", c.tgt)
}

func (c *PacketConn) InnerCipher() *ciphers.StreamCipher {
	switch innerConn := c.PacketConn.(type) {
	case *shadowsocks_stream.UdpConn:
		return innerConn.Cipher()
	default:
		return nil
	}
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *PacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.tgt)
}

func (c *PacketConn) ReadFrom(b []byte) (n int, from netip.AddrPort, err error) {
	n, err = c.PacketConn.Read(b)
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	decoded, err := c.Protocol.DecodePkt(b[:n])
	if err != nil {
		return n, netip.AddrPort{}, err
	}

	addr := socks.SplitAddr(decoded)
	if addr == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("no addr present")
	}

	from, err = netip.ParseAddrPort(addr.String())
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("bad addr: %w", err)
	}

	n = copy(b, decoded[len(addr):])
	return n, from, nil
}

func (c *PacketConn) WriteTo(b []byte, to string) (n int, err error) {
	addr, err := socks.ParseAddr(to)
	if err != nil {
		return 0, err
	}
	pb := pool.GetBuffer(len(addr) + len(b))
	copy(pb, addr)
	copy(pb[len(addr):], b)
	buf := bytes.NewBuffer(pb)
	if err = c.Protocol.EncodePkt(buf); err != nil {
		return 0, err
	}
	if _, err = c.PacketConn.Write(buf.Bytes()); err != nil {
		return 0, err
	}

	return len(b), err
}
