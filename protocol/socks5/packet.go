// Modified from https://github.com/nadoo/glider/tree/v0.16.2

package socks5

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
)

// PktConn .
type PktConn struct {
	net.Conn
	ctrlConn net.Conn // tcp control conn
}

// NewPktConn returns a PktConn, the writeAddr must be *net.UDPAddr or *net.UnixAddr.
func NewPktConn(c net.Conn, ctrlConn net.Conn) *PktConn {
	pc := &PktConn{
		Conn:     c,
		ctrlConn: ctrlConn,
	}

	go func() {
		buf := pool.GetBuffer(1)
		defer pool.PutBuffer(buf)
		for {
			_, err := ctrlConn.Read(buf)
			if err, ok := err.(net.Error); ok && err.Timeout() {
				continue
			}
			pc.Conn.Close()
			// log.F("[socks5] dialudp udp associate end")
			return
		}
	}()

	return pc
}

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

func (pc *PktConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ap, err := ToAddrPort(addr)
	if err != nil {
		return 0, err
	}
	return pc.WriteToAddrPort(b, ap)
}

func (pc *PktConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	var ap netip.AddrPort
	n, ap, err = pc.ReadFromAddrPort(b)
	return n, net.UDPAddrFromAddrPort(ap), err
}

func (pc *PktConn) ReadFromAddrPort(b []byte) (int, netip.AddrPort, error) {
	if len(b) < 22 {
		return 0, netip.AddrPort{}, errors.New("buffer too small")
	}

	n, err := pc.Conn.Read(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// RSV 2 + FRAG 1 + ATYP 1 + MIN_ADDR 4 + PORT 2
	if n < 10 {
		return 0, netip.AddrPort{}, errors.New("packet too short")
	}

	atyp := b[3]
	var addr netip.Addr
	var portOffset int

	switch atyp {
	case 0x01: // IPv4
		var ip [4]byte
		copy(ip[:], b[4:8])
		addr = netip.AddrFrom4(ip)
		portOffset = 8
	case 0x04: // IPv6
		var ip [16]byte
		copy(ip[:], b[4:20])
		addr = netip.AddrFrom16(ip)
		portOffset = 20
	case 0x03: // Domain
		return 0, netip.AddrPort{}, errors.New("domain address not supported in fast path")
	default:
		return 0, netip.AddrPort{}, errors.New("unknown address type")
	}

	port := binary.BigEndian.Uint16(b[portOffset : portOffset+2])
	ap := netip.AddrPortFrom(addr, port)

	dataOffset := portOffset + 2
	if n < dataOffset {
		return 0, netip.AddrPort{}, errors.New("invalid packet structure")
	}
	return copy(b, b[dataOffset:n]), ap, nil
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

	n, err := pc.Conn.Write(buf)
	if n > tgtLen+3 {
		return n - tgtLen - 3, err
	}
	return 0, err
}

// Close .
func (pc *PktConn) Close() error {
	return errors.Join(pc.ctrlConn.Close(), pc.Conn.Close())
}
