// Modified from https://github.com/nadoo/glider/tree/v0.16.2

package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/common"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// PktConn .
type PktConn struct {
	net.PacketConn
	ctrlConn net.Conn // tcp control conn
	server   net.Addr
}

// NewPktConn returns a PktConn, the writeAddr must be *net.UDPAddr or *net.UnixAddr.
func NewPktConn(c net.PacketConn, ctrlConn net.Conn, server net.Addr) *PktConn {
	pc := &PktConn{
		PacketConn: c,
		ctrlConn:   ctrlConn,
		server:     server,
	}

	go func() {
		buf := pool.GetBuffer(1)
		defer pool.PutBuffer(buf)
		for {
			_, err := ctrlConn.Read(buf)
			if err, ok := err.(net.Error); ok && err.Timeout() {
				continue
			}
			pc.PacketConn.Close()
			// log.F("[socks5] dialudp udp associate end")
			return
		}
	}()

	return pc
}

func (pc *PktConn) ReadFromAddrPort(b []byte) (int, netip.AddrPort, error) {
	buf := pool.GetBuffer(len(b) + 10)
	defer pool.PutBuffer(buf)

	n, _, err := pc.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// RSV 2 + FRAG 1 + ATYP 1 + MIN_ADDR 4 + PORT 2
	if n < 10 {
		return 0, netip.AddrPort{}, errors.New("packet too short")
	}

	atyp := buf[3]
	var addr netip.Addr
	var portOffset int

	switch atyp {
	case 0x01: // IPv4
		var ip [4]byte
		copy(ip[:], buf[4:8])
		addr = netip.AddrFrom4(ip)
		portOffset = 8
	case 0x04: // IPv6
		var ip [16]byte
		copy(ip[:], buf[4:20])
		addr = netip.AddrFrom16(ip)
		portOffset = 20
	case 0x03: // Domain
		return 0, netip.AddrPort{}, errors.New("domain address not supported in fast path")
	default:
		return 0, netip.AddrPort{}, errors.New("unknown address type")
	}

	port := binary.BigEndian.Uint16(buf[portOffset : portOffset+2])
	ap := netip.AddrPortFrom(addr, port)

	dataOffset := portOffset + 2
	if n < dataOffset {
		return 0, netip.AddrPort{}, errors.New("invalid packet structure")
	}
	return copy(b, buf[dataOffset:n]), ap, nil
}

// ReadFrom overrides the original function from transport.PacketConn.
func (pc *PktConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := pool.GetBuffer(len(b))
	defer pool.PutBuffer(buf)

	n, _, err = pc.PacketConn.ReadFrom(buf)
	if err != nil {
		return
	}

	if n < 3 {
		return n, nil, errors.New("not enough size to get addr")
	}

	// https://www.rfc-editor.org/rfc/rfc1928#section-7
	// +----+------+------+----------+----------+----------+
	// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	// +----+------+------+----------+----------+----------+
	// | 2  |  1   |  1   | Variable |    2     | Variable |
	// +----+------+------+----------+----------+----------+
	tgtAddr := socks.SplitAddr(buf[3:n])
	if tgtAddr == nil {
		return n, nil, errors.New("can not get target addr")
	}

	addr, err = common.ResolveUDPAddr(tgtAddr.String())
	if err != nil {
		return n, nil, errors.New("wrong target addr")
	}

	n = copy(b, buf[3+len(tgtAddr):n])
	return
}

func (pc *PktConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (int, error) {
	addr := ap.Addr()
	isIPv6 := addr.Is6()

	// SOCKS5 UDP Header Length
	// RSV(2) + FRAG(1) + ATYP(1) + ADDR(4/16) + PORT(2)
	addrLen := 4
	atyp := byte(0x01) // IPv4
	if isIPv6 {
		addrLen = 16
		atyp = byte(0x04) // IPv6
	}
	tgtLen := 1 + addrLen + 2

	buf := pool.GetBuffer(3 + tgtLen + len(b))
	defer pool.PutBuffer(buf)

	// Header
	buf[0], buf[1], buf[2] = 0, 0, 0 // RSV, FRAG
	buf[3] = atyp

	// IP + PORT
	copy(buf[4:], addr.AsSlice())
	binary.BigEndian.PutUint16(buf[4+addrLen:], ap.Port())

	// Payload
	copy(buf[3+tgtLen:], b)

	n, err := pc.PacketConn.WriteTo(buf, pc.server)
	if n > tgtLen+3 {
		return n - tgtLen - 3, err
	}
	return 0, err
}

// WriteTo overrides the original function from transport.PacketConn.
func (pc *PktConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	target, err := socks.ParseAddr(addr.String())
	if err != nil {
		return 0, fmt.Errorf("invalid addr: %w", err)
	}

	tgtLen := len(target)
	buf := pool.GetBuffer(3 + tgtLen + len(b))
	defer pool.PutBuffer(buf)

	copy(buf, []byte{0, 0, 0})
	copy(buf[3:], target)
	copy(buf[3+tgtLen:], b)

	n, err := pc.PacketConn.WriteTo(buf, pc.server)
	if n > tgtLen+3 {
		return n - tgtLen - 3, err
	}

	return 0, err
}

// Close .
func (pc *PktConn) Close() error {
	return errors.Join(pc.ctrlConn.Close(), pc.PacketConn.Close())
}
