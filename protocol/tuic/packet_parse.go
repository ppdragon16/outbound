package tuic

import (
	"encoding/binary"
	"fmt"
	"net"

)

// readPacketFromMessage parses a TUIC Packet command from its wire-format
// message (CommandHead + Packet fields + Address + DATA) using direct slice
// indexing, avoiding the per-call bytes.Reader allocation and binary.Read
// reflection overhead that dominate ReadPacket/ReadPacketWithHead.
//
// Hot path: processDatagram calls this for every inbound UDP datagram.
//
// Allocations: 4 (Packet + Address + ADDR slice + DATA slice), down from
// 12 via the reader+binary.Read path.
func readPacketFromMessage(msg []byte) (*Packet, error) {
	// VER(1) + TYPE(1) + ASSOC_ID(2) + PKT_ID(2) + FRAG_TOTAL(1) + FRAG_ID(1) + SIZE(2)
	const fixedLen = 2 + 2 + 2 + 1 + 1 + 2
	if len(msg) < fixedLen {
		return nil, fmt.Errorf("tuic: packet too short: %d bytes", len(msg))
	}
	if typ := CommandType(msg[1]); typ != PacketType {
		return nil, fmt.Errorf("tuic: not a packet command: %s", typ)
	}
	ver := msg[0]
	off := 2
	assocId := binary.BigEndian.Uint16(msg[off:])
	off += 2
	pktId := binary.BigEndian.Uint16(msg[off:])
	off += 2
	fragTotal := msg[off]
	off += 1
	fragId := msg[off]
	off += 1
	size := binary.BigEndian.Uint16(msg[off:])
	off += 2

	addr, n, err := readAddressFromSlice(msg[off:])
	if err != nil {
		return nil, err
	}
	off += n

	var data []byte
	if size > 0 {
		if len(msg[off:]) < int(size) {
			return nil, fmt.Errorf("tuic: data truncated: need %d have %d", size, len(msg[off:]))
		}
		data = make([]byte, size)
		copy(data, msg[off:off+int(size)])
	}

	return &Packet{
		CommandHead:  &CommandHead{VER: ver, TYPE: PacketType},
		ASSOC_ID:     assocId,
		PKT_ID:       pktId,
		FRAG_TOTAL:   fragTotal,
		FRAG_ID:      fragId,
		SIZE:         size,
		ADDR:         addr,
		DATA:         data,
	}, nil
}

// readAddressFromSlice parses an Address directly from a byte slice,
// returning the Address, the number of bytes consumed, and any error.
// Avoids the BufferedReader interface and io.ReadFull overhead.
func readAddressFromSlice(msg []byte) (*Address, int, error) {
	if len(msg) < 1 {
		return nil, 0, fmt.Errorf("tuic: address type byte missing")
	}
	typ := msg[0]
	off := 1
	var addr []byte
	switch typ {
	case AtypIPv4:
		const addrLen = net.IPv4len
		if len(msg[off:]) < addrLen+2 {
			return nil, 0, fmt.Errorf("tuic: ipv4 address too short")
		}
		addr = make([]byte, addrLen)
		copy(addr, msg[off:])
		off += addrLen
	case AtypIPv6:
		const addrLen = net.IPv6len
		if len(msg[off:]) < addrLen+2 {
			return nil, 0, fmt.Errorf("tuic: ipv6 address too short")
		}
		addr = make([]byte, addrLen)
		copy(addr, msg[off:])
		off += addrLen
	case AtypDomainName:
		if len(msg[off:]) < 1 {
			return nil, 0, fmt.Errorf("tuic: domain length byte missing")
		}
		addrLen := int(msg[off])
		if len(msg[off:]) < 1+addrLen+2 {
			return nil, 0, fmt.Errorf("tuic: domain address too short")
		}
		addr = make([]byte, 1+addrLen)
		addr[0] = byte(addrLen)
		copy(addr[1:], msg[off+1:off+1+addrLen])
		off += 1 + addrLen
	case AtypNone:
		// Address type None: no ADDR, no PORT (used on non-first fragments).
		return &Address{TYPE: typ}, off, nil
	default:
		return nil, 0, fmt.Errorf("tuic: unknown address type: %#x", typ)
	}
	if len(msg[off:]) < 2 {
		return nil, 0, fmt.Errorf("tuic: address port missing")
	}
	port := binary.BigEndian.Uint16(msg[off:])
	off += 2
	return &Address{TYPE: typ, ADDR: addr, PORT: port}, off, nil
}
