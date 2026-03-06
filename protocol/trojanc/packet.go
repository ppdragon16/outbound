package trojanc

import (
	"bytes"
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

// ReadFrom reads a UDP packet according to Trojan UDP format:
// +------+----------+----------+--------+---------+----------+
// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
// +------+----------+----------+--------+---------+----------+
// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
// +------+----------+----------+--------+---------+----------+
func (c *PacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	// Decode address using shadowsocks implementation
	addr, err = socks5.ReadAddr(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read address: %w", err)
	}

	// Read payload length (2 bytes)
	var payloadLen uint16
	if err := binary.Read(c.Conn, binary.BigEndian, &payloadLen); err != nil {
		return 0, nil, fmt.Errorf("failed to read payload length: %w", err)
	}

	// Read CRLF
	buf := pool.GetBuffer(int(payloadLen) + 2)
	defer pool.PutBuffer(buf)

	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return 0, nil, fmt.Errorf("failed to read payload: %w", err)
	}

	if !bytes.Equal(CRLF, buf[:2]) {
		return 0, nil, fmt.Errorf("invalid CRLF in UDP packet")
	}

	n = copy(b, buf[2:])
	return
}

// WriteTo writes a UDP packet according to Trojan UDP format
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {

	// Build UDP packet using bytes.Buffer
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)

	// Encode address
	err = socks5.WriteAddr(addr.String(), buf)
	if err != nil {
		return 0, fmt.Errorf("failed to encode address: %w", err)
	}

	// Write payload length
	binary.Write(buf, binary.BigEndian, uint16(len(b)))

	// Write CRLF
	buf.Write(CRLF)

	// Write payload
	buf.Write(b)

	// Send the complete packet
	if _, err := c.Conn.Write(buf.Bytes()); err != nil {
		return 0, fmt.Errorf("failed to write UDP packet: %w", err)
	}

	return len(b), nil
}

func (c *PacketConn) ReadFromAddrPort(b []byte) (int, netip.AddrPort, error) {
	ap, err := socks5.ReadAddrPort(c.Conn)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
		return 0, ap, err
	}
	payloadLen := binary.BigEndian.Uint16(lenBuf[:])

	if len(b) < int(payloadLen)+2 {
		return 0, ap, fmt.Errorf("buffer too small")
	}

	// Read CRLF + Payload
	if _, err := io.ReadFull(c.Conn, b[:2+payloadLen]); err != nil {
		return 0, ap, err
	}

	if !bytes.Equal(CRLF, b[:2]) {
		return 0, ap, fmt.Errorf("invalid CRLF")
	}

	return copy(b, b[2:2+payloadLen]), ap, nil
}

func (c *PacketConn) WriteToAddrPort(b []byte, ap netip.AddrPort) (int, error) {
	addr := ap.Addr()
	isV4 := addr.Is4()

	// ATYP(1) + ADDR(4/16) + PORT(2) + PAYLOAD_LEN(2) + CRLF(2)
	headerLen := 7 + 2 + 2
	if !isV4 {
		headerLen = 19 + 2 + 2
	}

	totalLen := headerLen + len(b)
	buf := pool.GetBuffer(totalLen)
	defer pool.PutBuffer(buf)

	// ATYP
	if isV4 {
		buf[0] = byte(socks5.AddressTypeIPv4)
		copy(buf[1:5], addr.AsSlice())
		binary.BigEndian.PutUint16(buf[5:7], ap.Port())
	} else {
		buf[0] = byte(socks5.AddressTypeIPv6)
		copy(buf[1:17], addr.AsSlice())
		binary.BigEndian.PutUint16(buf[17:19], ap.Port())
	}

	// Payload Length, CRLF, Payload
	binary.BigEndian.PutUint16(buf[headerLen-4:headerLen-2], uint16(len(b)))
	copy(buf[headerLen-2:headerLen], CRLF)
	copy(buf[headerLen:], b)

	if _, err := c.Conn.Write(buf); err != nil {
		return 0, err
	}

	return len(b), nil
}
