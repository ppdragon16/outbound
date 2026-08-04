package tuic

import (
	"encoding/binary"
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/quic-go"
)

// buildPacketBuf builds a complete tuic packet (header + payload) into a pooled []byte.
// Wire format:
//
//	[VER(1)][TYPE(1)][ASSOC_ID(2)][PKT_ID(2)][FRAG_TOTAL(1)][FRAG_ID(1)][SIZE(2)]
//	[ADDR_TYPE(1)][ADDR(var)][PORT(2)][DATA(var)]
func buildPacketBuf(connId, pktId uint16, fragTotal, fragId uint8, data []byte, addr netip.AddrPort) []byte {
	var addrType byte
	var addrRaw []byte
	if addr.Addr().Is4() {
		addrType = AtypIPv4
		addrRaw = addr.Addr().AsSlice()
	} else {
		addrType = AtypIPv6
		addrRaw = addr.Addr().AsSlice()
	}
	// header: 2 + 2+2+1+1+2 = 10, plus addr: 1 + len(addrRaw) + 2
	headerSize := 10 + 1 + len(addrRaw) + 2
	totalSize := headerSize + len(data)
	buf := pool.GetBuffer(totalSize)
	off := 0
	buf[off] = Ver5
	off++
	buf[off] = byte(PacketType)
	off++
	binary.BigEndian.PutUint16(buf[off:], connId)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], pktId)
	off += 2
	buf[off] = fragTotal
	off++
	buf[off] = fragId
	off++
	binary.BigEndian.PutUint16(buf[off:], uint16(len(data)))
	off += 2
	buf[off] = addrType
	off++
	copy(buf[off:], addrRaw)
	off += len(addrRaw)
	binary.BigEndian.PutUint16(buf[off:], addr.Port())
	off += 2
	copy(buf[off:], data)
	return buf
}

// buildPacketBufAddrNone builds a tuic packet without address (ATYP_NONE).
// Used for non-first fragments of a fragmented UDP packet.
func buildPacketBufAddrNone(connId, pktId uint16, fragTotal, fragId uint8, data []byte) []byte {
	// header: 2 + 2+2+1+1+2 = 10, plus AtypNone: 1
	headerSize := 10 + 1
	totalSize := headerSize + len(data)
	buf := pool.GetBuffer(totalSize)
	off := 0
	buf[off] = Ver5
	off++
	buf[off] = byte(PacketType)
	off++
	binary.BigEndian.PutUint16(buf[off:], connId)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], pktId)
	off += 2
	buf[off] = fragTotal
	off++
	buf[off] = fragId
	off++
	binary.BigEndian.PutUint16(buf[off:], uint16(len(data)))
	off += 2
	buf[off] = AtypNone
	off++
	copy(buf[off:], data)
	return buf
}

// fragWriteNative sends a large UDP packet via multiple QUIC datagrams.
// Each fragment is built directly into a pool buffer — no *Packet allocations.
func fragWriteNative(quicConn quic.Connection, connId, pktId uint16, addr netip.AddrPort, fullPayload []byte, fragSize int) error {
	if fragSize == 0 {
		fragSize = 1
	}
	off := 0
	fragID := uint8(0)
	fragCount := uint8((len(fullPayload) + fragSize - 1) / fragSize)
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > fragSize {
			payloadSize = fragSize
		}
		chunk := fullPayload[off : off+payloadSize]
		off += payloadSize

		var buf []byte
		if fragID == 0 {
			// First fragment: includes full address.
			buf = buildPacketBuf(connId, pktId, fragCount, fragID, chunk, addr)
		} else {
			// Subsequent fragments: address type is NONE.
			buf = buildPacketBufAddrNone(connId, pktId, fragCount, fragID, chunk)
		}
		err := quicConn.SendDatagram(buf)
		pool.PutBuffer(buf)
		if err != nil {
			return err
		}
		fragID++
	}
	return nil
}

// deFragger reassembles fragmented tuic UDP packets by PKT_ID.
type deFragger struct {
	pkgID uint16
	frags []*Packet
	count uint8
}

// Feed feeds a fragment and returns the assembled result when complete.
// Caller must call m.Release() when assembled is true (Feed releases stored
// fragments on assembly but the caller owns m when FRAG_TOTAL <= 1).
func (d *deFragger) Feed(m *Packet, p []byte) (n int, addrPort netip.AddrPort, assembled bool) {
	if m.FRAG_TOTAL <= 1 {
		addr, _ := netip.AddrFromSlice(m.ADDR.ADDR)
		return copy(p, m.DATA), netip.AddrPortFrom(addr, m.ADDR.PORT), true
	}
	if m.FRAG_ID >= m.FRAG_TOTAL {
		// Invalid fragment: release immediately.
		m.Release()
		return
	}
	if d.count == 0 {
		d.pkgID = m.PKT_ID
		d.frags = make([]*Packet, m.FRAG_TOTAL)
		d.count = 1
		d.frags[m.FRAG_ID] = m
	} else if d.frags[m.FRAG_ID] == nil {
		d.frags[m.FRAG_ID] = m
		d.count++
		if int(d.count) == len(d.frags) {
			for _, frag := range d.frags {
				if n >= len(p) {
					break
				}
				n += copy(p[n:], frag.DATA)
			}
			// Capture addrPort before releasing (Release nils frag.ADDR).
			addr, _ := netip.AddrFromSlice(d.frags[0].ADDR.ADDR)
			addrPort = netip.AddrPortFrom(addr, d.frags[0].ADDR.PORT)
			// Release all assembled fragments back to pools.
			for _, frag := range d.frags {
				frag.Release()
			}
			d.frags = nil
			d.count = 0
			return n, addrPort, true
		}
	}
	return
}
