package trojanc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
)

type PacketConn struct {
	*Conn
}

// ReadFrom reads a UDP packet according to Trojan UDP format:
// +------+----------+----------+--------+---------+----------+
// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
// +------+----------+----------+--------+---------+----------+
// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
// +------+----------+----------+--------+---------+----------+
func (c *PacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	// Decode address using shadowsocks implementation
	addressInfo, err := shadowsocks.DecodeAddress(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to decode address: %w", err)
	}

	// Create address object (only support IP addresses for UDP)
	switch addressInfo.Type {
	case shadowsocks.AddressTypeIPv4, shadowsocks.AddressTypeIPv6:
		addr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(addressInfo.IP, addressInfo.Port))
	default:
		return 0, nil, fmt.Errorf("unsupported address type for UDP: %v", addressInfo.Type)
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
	// Parse the destination address
	addressInfo, err := shadowsocks.AddressFromString(addr.String())
	if err != nil {
		return 0, fmt.Errorf("failed to parse destination address: %w", err)
	}

	// Build UDP packet using bytes.Buffer
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)

	// Encode address
	addressBytes, _, err := shadowsocks.EncodeAddress(addressInfo)
	if err != nil {
		return 0, fmt.Errorf("failed to encode address: %w", err)
	}

	// Write address
	buf.Write(addressBytes)

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
