package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"unsafe"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/quic-go/quicvarint"
	"github.com/samber/oops"
)

const (
	FrameTypeTCPRequest = 0x401

	// Max length values are for preventing DoS attacks

	MaxAddressLength = 2048
	MaxMessageLength = 2048
	MaxPaddingLength = 4096

	MaxUDPSize = 4096

	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

// TCPRequest format:
// 0x401 (QUIC varint)
// Address length (QUIC varint)
// Address (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPRequest(r io.Reader) (string, error) {
	bReader := quicvarint.NewReader(r)
	addrLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if addrLen == 0 || addrLen > MaxAddressLength {
		return "", oops.Tags("protocol error").New("invalid address length")
	}
	var addrBuf []byte
	if addrLen <= 256 {
		var stackBuf [256]byte
		addrBuf = stackBuf[:addrLen]
	} else {
		addrBuf = make([]byte, addrLen)
	}
	_, err = io.ReadFull(r, addrBuf)
	if err != nil {
		return "", err
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if paddingLen > MaxPaddingLength {
		return "", oops.Tags("protocol error").New("invalid padding length")
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return "", err
		}
	}
	return string(addrBuf), nil
}

func WriteTCPRequest(w io.Writer, addr string) error {
	paddingLen := tcpRequestPadding.randomLen()
	addrLen := len(addr)
	sz := int(quicvarint.Len(FrameTypeTCPRequest)) +
		int(quicvarint.Len(uint64(addrLen))) + addrLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := pool.GetBuffer(sz)
	defer pool.PutBuffer(buf)
	i := varintPut(buf, FrameTypeTCPRequest)
	i += varintPut(buf[i:], uint64(addrLen))
	i += copy(buf[i:], addr)
	i += varintPut(buf[i:], uint64(paddingLen))
	writeRandomBytes(buf[i : i+paddingLen])
	_, err := w.Write(buf)
	return err
}

// TCPResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (QUIC varint)
// Message (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", err
	}
	bReader := quicvarint.NewReader(r)
	msgLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if msgLen > MaxMessageLength {
		return false, "", oops.Tags("protocol error").New("invalid message length")
	}
	var msgBuf []byte
	if msgLen > 0 {
		if msgLen <= 256 {
			var stackBuf [256]byte
			msgBuf = stackBuf[:msgLen]
		} else {
			msgBuf = make([]byte, msgLen)
		}
		_, err = io.ReadFull(r, msgBuf)
		if err != nil {
			return false, "", err
		}
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if paddingLen > MaxPaddingLength {
		return false, "", oops.Tags("protocol error").New("invalid padding length")
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return false, "", err
		}
	}
	return status[0] == 0, string(msgBuf), nil
}

func WriteTCPResponse(w io.Writer, ok bool, msg string) error {
	paddingLen := tcpResponsePadding.randomLen()
	msgLen := len(msg)
	sz := 1 + int(quicvarint.Len(uint64(msgLen))) + msgLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := pool.GetBuffer(sz)
	defer pool.PutBuffer(buf)
	if ok {
		buf[0] = 0
	} else {
		buf[0] = 1
	}
	i := varintPut(buf[1:], uint64(msgLen))
	i += copy(buf[1+i:], msg)
	i += varintPut(buf[1+i:], uint64(paddingLen))
	writeRandomBytes(buf[1+i : 1+i+paddingLen])
	_, err := w.Write(buf)
	return err
}

// UDPMessage format:
// Session ID (uint32 BE)
// Packet ID (uint16 BE)
// Fragment ID (uint8)
// Fragment count (uint8)
// Address length (QUIC varint)
// Address (bytes)
// Data...

type UDPMessage struct {
	SessionID uint32 // 4
	PacketID  uint16 // 2
	FragID    uint8  // 1
	FragCount uint8  // 1
	AddrPort  netip.AddrPort
	Data      []byte
	// DataBuf holds the full-cap datagram buffer backing Data.
	// Set only for inbound messages (from quic-go's ReceiveDatagram);
	// nil for outbound.  Used by Defragger to release pooled buffers.
	DataBuf []byte
}

func (m UDPMessage) HeaderSize() int {
	lAddr := addrPortStrLen(m.AddrPort)
	return 4 + 2 + 1 + 1 + int(quicvarint.Len(uint64(lAddr))) + lAddr
}

func (m UDPMessage) Size() int {
	return m.HeaderSize() + len(m.Data)
}

func (m UDPMessage) Serialize(buf []byte) int {
	// Make sure the buffer is big enough
	if len(buf) < m.Size() {
		return -1
	}
	binary.BigEndian.PutUint32(buf, m.SessionID)
	binary.BigEndian.PutUint16(buf[4:], m.PacketID)
	buf[6] = m.FragID
	buf[7] = m.FragCount
	lAddr := addrPortStrLen(m.AddrPort)
	i := varintPut(buf[8:], uint64(lAddr))
	i += putAddrPort(buf[8+i:], m.AddrPort)
	i += copy(buf[8+i:], m.Data)
	return 8 + i
}

// addrPortStrLen returns the wire-format string length of an AddrPort.
// IPv4: "1.2.3.4:443", IPv6: "[::1]:443".
func addrPortStrLen(ap netip.AddrPort) int {
	addr := ap.Addr()
	if addr.Is4() {
		ip4 := addr.As4()
		return byteWidth(ip4[0]) + 1 + byteWidth(ip4[1]) + 1 +
			byteWidth(ip4[2]) + 1 + byteWidth(ip4[3]) + 1 +
			lenUint16(ap.Port())
	}
	// IPv6: [...] + colon + port
	return 1 + ipv6CanonicalLen(addr.As16()) + 1 + 1 + lenUint16(ap.Port())
}

// putAddrPort writes the wire-format string representation of ap into buf.
// Returns bytes written. buf must have at least addrPortStrLen(ap) bytes.
func putAddrPort(buf []byte, ap netip.AddrPort) int {
	addr := ap.Addr()
	if addr.Is4() {
		ip4 := addr.As4()
		n := putByte(buf, ip4[0])
		buf[n] = '.'
		n++
		n += putByte(buf[n:], ip4[1])
		buf[n] = '.'
		n++
		n += putByte(buf[n:], ip4[2])
		buf[n] = '.'
		n++
		n += putByte(buf[n:], ip4[3])
		buf[n] = ':'
		n++
		n += putUint16(buf[n:], ap.Port())
		return n
	}
	// IPv6
	buf[0] = '['
	end := addr.AppendTo(buf[1:1])
	n := 1 + len(end)
	buf[n] = ']'
	n++
	buf[n] = ':'
	n++
	n += putUint16(buf[n:], ap.Port())
	return n
}

// ipv6CanonicalLen returns the length of the canonical RFC 5952 string
// representation of an IPv6 address without brackets.
func ipv6CanonicalLen(ip [16]byte) int {
	hextets := [8]int{
		int(ip[0])<<8 | int(ip[1]),
		int(ip[2])<<8 | int(ip[3]),
		int(ip[4])<<8 | int(ip[5]),
		int(ip[6])<<8 | int(ip[7]),
		int(ip[8])<<8 | int(ip[9]),
		int(ip[10])<<8 | int(ip[11]),
		int(ip[12])<<8 | int(ip[13]),
		int(ip[14])<<8 | int(ip[15]),
	}

	// Find longest zero run (RFC 5952: leftmost when tied).
	bestStart, bestLen := 0, 0
	for i := 0; i < 8; {
		if hextets[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && hextets[j] == 0 {
			j++
		}
		if run := j - i; run > bestLen {
			bestStart, bestLen = i, run
		}
		i = j
	}

	total := 0

	// Groups before the compressed run.
	for i := 0; i < bestStart; i++ {
		if i > 0 {
			total++ // ':'
		}
		total += hexDigitCount(hextets[i])
	}

	// "::" — provides its own separator from the left part.
	if bestLen > 0 {
		total += 2
	}

	// Groups after the compressed run.
	for i := bestStart + bestLen; i < 8; i++ {
		if i > bestStart+bestLen {
			total++ // ':'
		}
		total += hexDigitCount(hextets[i])
	}

	return total
}

// hexDigitCount returns the number of lowercase hex digits needed for v,
// with no leading zeros (except 0 itself, which needs 1 digit).
func hexDigitCount(v int) int {
	switch {
	case v < 0x10:
		return 1
	case v < 0x100:
		return 2
	case v < 0x1000:
		return 3
	default:
		return 4
	}
}

// byteWidth returns the number of decimal digits in v.
func byteWidth(v byte) int {
	if v < 10 {
		return 1
	}
	if v < 100 {
		return 2
	}
	return 3
}

// putByte writes the decimal representation of v into buf.
// Returns bytes written.
func putByte(buf []byte, v byte) int {
	if v >= 100 {
		buf[0] = byte(v/100) + '0'
		buf[1] = byte(v/10%10) + '0'
		buf[2] = byte(v%10) + '0'
		return 3
	}
	if v >= 10 {
		buf[0] = byte(v/10) + '0'
		buf[1] = byte(v%10) + '0'
		return 2
	}
	buf[0] = byte(v) + '0'
	return 1
}

// lenUint16 returns the number of decimal digits needed to represent n.
func lenUint16(n uint16) int {
	switch {
	case n < 10:
		return 1
	case n < 100:
		return 2
	case n < 1000:
		return 3
	case n < 10000:
		return 4
	default:
		return 5
	}
}

// putUint16 writes the decimal representation of v into buf.
// Returns bytes written.
func putUint16(buf []byte, v uint16) int {
	if v >= 10000 {
		buf[0] = byte(v/10000) + '0'
		v %= 10000
		buf[1] = byte(v/1000) + '0'
		v %= 1000
		buf[2] = byte(v/100) + '0'
		v %= 100
		buf[3] = byte(v/10) + '0'
		buf[4] = byte(v%10) + '0'
		return 5
	}
	if v >= 1000 {
		buf[0] = byte(v/1000) + '0'
		v %= 1000
		buf[1] = byte(v/100) + '0'
		v %= 100
		buf[2] = byte(v/10) + '0'
		buf[3] = byte(v%10) + '0'
		return 4
	}
	if v >= 100 {
		buf[0] = byte(v/100) + '0'
		v %= 100
		buf[1] = byte(v/10) + '0'
		buf[2] = byte(v%10) + '0'
		return 3
	}
	if v >= 10 {
		buf[0] = byte(v/10) + '0'
		buf[1] = byte(v%10) + '0'
		return 2
	}
	buf[0] = byte(v) + '0'
	return 1
}

// parseAddrPortBytes parses a wire-format address (IP:port or [IP]:port)
// directly from bytes into netip.AddrPort without intermediate string allocation.
func parseAddrPortBytes(b []byte) (netip.AddrPort, error) {
	if len(b) == 0 {
		return netip.AddrPort{}, fmt.Errorf("empty address")
	}
	if b[0] == '[' {
		// IPv6: [addr]:port
		closeBracket := -1
		for i := 1; i < len(b); i++ {
			if b[i] == ']' {
				closeBracket = i
				break
			}
		}
		if closeBracket < 0 || closeBracket+1 >= len(b) || b[closeBracket+1] != ':' {
			return netip.AddrPort{}, fmt.Errorf("malformed ipv6 address: %s", string(b))
		}
		addr, err := netip.ParseAddr(unsafe.String(&b[1], closeBracket-1))
		if err != nil {
			return netip.AddrPort{}, err
		}
		port, err := parseUint16(b[closeBracket+2:])
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(addr, port), nil
	}
	// IPv4: a.b.c.d:port — find last colon
	lastColon := -1
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == ':' {
			lastColon = i
			break
		}
	}
	if lastColon < 0 {
		return netip.AddrPort{}, fmt.Errorf("malformed ipv4 address: %s", string(b))
	}
	ipBytes := b[:lastColon]
	port, err := parseUint16(b[lastColon+1:])
	if err != nil {
		return netip.AddrPort{}, err
	}
	// Parse dotted-decimal IPv4
	var ip [4]byte
	start := 0
	for i := range 4 {
		end := start
		for end < len(ipBytes) && ipBytes[end] != '.' {
			end++
		}
		if end == start {
			return netip.AddrPort{}, fmt.Errorf("malformed ipv4 address: %s", string(b))
		}
		val, err := parseUint8(ipBytes[start:end])
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("invalid ipv4 octet: %s", string(ipBytes[start:end]))
		}
		ip[i] = val
		start = end + 1
	}
	return netip.AddrPortFrom(netip.AddrFrom4(ip), port), nil
}

func parseUint16(b []byte) (uint16, error) {
	var n uint16
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port: %s", string(b))
		}
		n = n*10 + uint16(c-'0')
	}
	return n, nil
}

func parseUint8(b []byte) (byte, error) {
	var n byte
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid number: %s", string(b))
		}
		n = n*10 + byte(c-'0')
	}
	return n, nil
}

func ParseUDPMessage(msg []byte, m *UDPMessage) error {
	if len(msg) < 9 {
		return oops.Tags("protocol error").New("message too short")
	}
	m.SessionID = binary.BigEndian.Uint32(msg)
	m.PacketID = binary.BigEndian.Uint16(msg[4:])
	m.FragID = msg[6]
	m.FragCount = msg[7]

	lAddr, varintLen := varintParse(msg[8:])
	if varintLen < 0 || lAddr == 0 || lAddr > MaxMessageLength {
		return oops.Tags("protocol error").New("invalid address length")
	}

	addrStart := 8 + varintLen
	addrEnd := addrStart + int(lAddr)
	if len(msg) <= addrEnd {
		return oops.Tags("protocol error").New("invalid message length")
	}
	ap, err := parseAddrPortBytes(msg[addrStart:addrEnd])
	if err != nil {
		return oops.Tags("protocol error").Wrap(err)
	}
	m.AddrPort = ap
	m.Data = msg[addrEnd:]
	m.DataBuf = nil // caller must set
	return nil
}

// varintParse reads a QUIC varint from a byte slice.
// Returns (value, bytesRead) or (0, -1) if the buffer is too short.
func varintParse(b []byte) (uint64, int) {
	if len(b) < 1 {
		return 0, -1
	}
	switch b[0] >> 6 {
	case 0:
		return uint64(b[0]), 1
	case 1:
		if len(b) < 2 {
			return 0, -1
		}
		return uint64(b[0]&0x3f)<<8 | uint64(b[1]), 2
	case 2:
		if len(b) < 4 {
			return 0, -1
		}
		return uint64(b[0]&0x3f)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3]), 4
	case 3:
		if len(b) < 8 {
			return 0, -1
		}
		return uint64(b[0]&0x3f)<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
			uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7]), 8
	}
	return 0, -1
}

// varintPut is like quicvarint.Append, but instead of appending to a slice,
// it writes to a fixed-size buffer. Returns the number of bytes written.
func varintPut(b []byte, i uint64) int {
	if i <= maxVarInt1 {
		b[0] = uint8(i)
		return 1
	}
	if i <= maxVarInt2 {
		b[0] = uint8(i>>8) | 0x40
		b[1] = uint8(i)
		return 2
	}
	if i <= maxVarInt4 {
		b[0] = uint8(i>>24) | 0x80
		b[1] = uint8(i >> 16)
		b[2] = uint8(i >> 8)
		b[3] = uint8(i)
		return 4
	}
	if i <= maxVarInt8 {
		b[0] = uint8(i>>56) | 0xc0
		b[1] = uint8(i >> 48)
		b[2] = uint8(i >> 40)
		b[3] = uint8(i >> 32)
		b[4] = uint8(i >> 24)
		b[5] = uint8(i >> 16)
		b[6] = uint8(i >> 8)
		b[7] = uint8(i)
		return 8
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}
