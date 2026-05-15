package protocol

import (
	"encoding/binary"
	"fmt"
	"io"

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
	padding := tcpRequestPadding.String()
	paddingLen := len(padding)
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
	copy(buf[i:], padding)
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
	padding := tcpResponsePadding.String()
	paddingLen := len(padding)
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
	copy(buf[1+i:], padding)
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
	Addr      string // varint + bytes
	Data      []byte
}

func (m *UDPMessage) HeaderSize() int {
	lAddr := len(m.Addr)
	return 4 + 2 + 1 + 1 + int(quicvarint.Len(uint64(lAddr))) + lAddr
}

func (m *UDPMessage) Size() int {
	return m.HeaderSize() + len(m.Data)
}

func (m *UDPMessage) Serialize(buf []byte) int {
	// Make sure the buffer is big enough
	if len(buf) < m.Size() {
		return -1
	}
	binary.BigEndian.PutUint32(buf, m.SessionID)
	binary.BigEndian.PutUint16(buf[4:], m.PacketID)
	buf[6] = m.FragID
	buf[7] = m.FragCount
	i := varintPut(buf[8:], uint64(len(m.Addr)))
	i += copy(buf[8+i:], m.Addr)
	i += copy(buf[8+i:], m.Data)
	return 8 + i
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
	m.Addr = string(msg[addrStart:addrEnd])
	m.Data = msg[addrEnd:]
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
