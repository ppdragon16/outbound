package trojanc

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

type PacketConn struct {
	net.Conn
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

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ap, err := ToAddrPort(addr)
	if err != nil {
		return 0, err
	}
	return c.WriteToAddrPort(b, ap)
}

// ReadFrom reads a UDP packet according to Trojan UDP format:
// +------+----------+----------+--------+---------+----------+
// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
// +------+----------+----------+--------+---------+----------+
// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
// +------+----------+----------+--------+---------+----------+
func (c *PacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	var ap netip.AddrPort
	n, ap, err = c.ReadFromAddrPort(b)
	return n, net.UDPAddrFromAddrPort(ap), err
}

func (c *PacketConn) ReadFromAddrPort(b []byte) (int, netip.AddrPort, error) {
	// Use a small stack buffer to read the header in fewer operations.
	// Max Header: ATYP(1) + IPv6(16) + Port(2) + Len(2) + CRLF(2) = 23 bytes.
	var headerStack [32]byte

	// 1. Read ATYP first to determine the address length
	if _, err := io.ReadFull(c.Conn, headerStack[:1]); err != nil {
		return 0, netip.AddrPort{}, err
	}

	var addrLen int
	atyp := headerStack[0]
	switch atyp {
	case byte(socks5.AddressTypeIPv4):
		addrLen = 4
	case byte(socks5.AddressTypeIPv6):
		addrLen = 16
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("unsupported atyp: %v", atyp)
	}

	// 2. Read the rest of the header: Address + Port + PayloadLen + CRLF
	// Length: addrLen + 2 (port) + 2 (len) + 2 (crlf)
	remainingHeaderLen := addrLen + 6
	headerTail := headerStack[1 : 1+remainingHeaderLen]
	if _, err := io.ReadFull(c.Conn, headerTail); err != nil {
		return 0, netip.AddrPort{}, err
	}

	// 3. Parse Address and Port (Zero-allocation)
	var addr netip.Addr
	if atyp == byte(socks5.AddressTypeIPv4) {
		addr = netip.AddrFrom4(*(*[4]byte)(headerTail[:4]))
	} else {
		addr = netip.AddrFrom16(*(*[16]byte)(headerTail[:16]))
	}
	port := binary.BigEndian.Uint16(headerTail[addrLen : addrLen+2])
	ap := netip.AddrPortFrom(addr, port)

	// 4. Parse Payload Length and Validate CRLF
	payloadLen := int(binary.BigEndian.Uint16(headerTail[addrLen+2 : addrLen+4]))
	if headerTail[addrLen+4] != 0x0D || headerTail[addrLen+5] != 0x0A {
		return 0, ap, fmt.Errorf("invalid CRLF")
	}

	// 5. Read Payload directly into user buffer
	if len(b) < payloadLen {
		return 0, ap, io.ErrShortBuffer
	}
	n, err := io.ReadFull(c.Conn, b[:payloadLen])
	return n, ap, err
}

func (c *PacketConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (int, error) {
	addr := ap.Addr()
	isV4 := addr.Is4()

	// 1. Calculate header size accurately
	// IPv4: 1 + 4 + 2 + 2 + 2 = 11
	// IPv6: 1 + 16 + 2 + 2 + 2 = 23
	addrFieldLen := 16
	if isV4 {
		addrFieldLen = 4
	}
	headerLen := 1 + addrFieldLen + 2 + 2 + 2

	totalLen := headerLen + len(b)
	buf := pool.GetBuffer(totalLen)
	defer pool.PutBuffer(buf)

	// 2. Build Header
	if isV4 {
		buf[0] = byte(socks5.AddressTypeIPv4)
		ip4 := addr.As4()
		copy(buf[1:5], ip4[:])
		binary.BigEndian.PutUint16(buf[5:7], ap.Port())
	} else {
		buf[0] = byte(socks5.AddressTypeIPv6)
		ip16 := addr.As16()
		copy(buf[1:17], ip16[:])
		binary.BigEndian.PutUint16(buf[17:19], ap.Port())
	}

	// Payload Length, CRLF, and Payload
	binary.BigEndian.PutUint16(buf[headerLen-4:headerLen-2], uint16(len(b)))
	buf[headerLen-2] = 0x0D
	buf[headerLen-1] = 0x0A
	copy(buf[headerLen:], b)

	// 3. Atomic Write
	_, err := c.Conn.Write(buf[:totalLen])
	if err != nil {
		return 0, err
	}

	return len(b), nil
}
