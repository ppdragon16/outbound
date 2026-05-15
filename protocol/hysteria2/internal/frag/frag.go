package frag

import (
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

func FragUDPMessage(m *protocol.UDPMessage, maxSize int) []protocol.UDPMessage {
	if m.Size() <= maxSize {
		return []protocol.UDPMessage{*m}
	}
	fullPayload := m.Data
	maxPayloadSize := maxSize - m.HeaderSize()
	off := 0
	fragID := uint8(0)
	fragCount := uint8((len(fullPayload) + maxPayloadSize - 1) / maxPayloadSize) // round up
	frags := make([]protocol.UDPMessage, fragCount)
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > maxPayloadSize {
			payloadSize = maxPayloadSize
		}
		frag := *m
		frag.FragID = fragID
		frag.FragCount = fragCount
		frag.Data = fullPayload[off : off+payloadSize]
		frags[fragID] = frag
		off += payloadSize
		fragID++
	}
	return frags
}

// Defragger handles the defragmentation of UDP messages.
// The current implementation can only handle one packet ID at a time.
// If another packet arrives before a packet has received all fragments
// in their entirety, any previous state is discarded.
type Defragger struct {
	pktID uint16
	frags [][]byte
	count uint8
}

func (d *Defragger) Feed(m *protocol.UDPMessage, p []byte) (int, bool) {
	if m.FragCount <= 1 {
		return copy(p, m.Data), true
	}
	if m.FragID >= m.FragCount {
		return 0, false
	}
	if m.PacketID != d.pktID || m.FragCount != uint8(len(d.frags)) {
		d.pktID = m.PacketID
		// reuse existing slice if capacity allows
		if int(m.FragCount) <= cap(d.frags) {
			d.frags = d.frags[:m.FragCount]
			clear(d.frags)
		} else {
			d.frags = make([][]byte, m.FragCount)
		}
		d.frags[m.FragID] = m.Data
		d.count = 1
	} else if d.frags[m.FragID] == nil {
		d.frags[m.FragID] = m.Data
		d.count++
		if int(d.count) == len(d.frags) {
			// all fragments received, assemble
			off := 0
			for _, data := range d.frags {
				off += copy(p[off:], data)
			}
			return off, true
		}
	}
	return 0, false
}

func (d *Defragger) Close() error {
	return nil
}
