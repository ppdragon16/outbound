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

// fragPiece holds a fragment's data slice together with a function that
// releases the backing buffer back to quic-go's datagram pool. Fragments
// reference the pool buffer indirectly (via msg.Data = msg[addrEnd:]), so
// the release callback closes over the original full-cap buffer — calling
// ReleaseDatagram on the sub-slice alone would silently fail the cap check.
type fragPiece struct {
	data    []byte
	release func()
}

// Defragger handles the defragmentation of UDP messages.
// The current implementation can only handle one packet ID at a time.
// If another packet arrives before a packet has received all fragments
// in their entirety, any previous state is discarded.
type Defragger struct {
	pktID uint16
	frags []fragPiece
	count uint8
}

// releaseAll calls the release callback on every stored fragment and resets
// the frags slice to zero values. Safe to call when no fragments are stored.
func (d *Defragger) releaseAll() {
	for i := range d.frags {
		if d.frags[i].release != nil {
			d.frags[i].release()
			d.frags[i].release = nil
		}
		d.frags[i].data = nil
	}
}

func (d *Defragger) Feed(m *protocol.UDPMessage, p []byte) (int, bool) {
	if m.FragCount <= 1 {
		n := copy(p, m.Data)
		if m.Release != nil {
			m.Release()
		}
		return n, true
	}
	if m.FragID >= m.FragCount {
		// Invalid fragment ID: release the current buffer.
		if m.Release != nil {
			m.Release()
		}
		return 0, false
	}
	if m.PacketID != d.pktID || m.FragCount != uint8(len(d.frags)) {
		// New packet: release previously held fragments before overwriting.
		d.releaseAll()
		d.pktID = m.PacketID
		// reuse existing slice if capacity allows
		if int(m.FragCount) <= cap(d.frags) {
			d.frags = d.frags[:m.FragCount]
		} else {
			d.frags = make([]fragPiece, m.FragCount)
		}
		d.frags[m.FragID] = fragPiece{data: m.Data, release: m.Release}
		d.count = 1
	} else if d.frags[m.FragID].data == nil {
		d.frags[m.FragID] = fragPiece{data: m.Data, release: m.Release}
		d.count++
		if int(d.count) == len(d.frags) {
			// all fragments received, assemble and release
			off := 0
			for i := range d.frags {
				off += copy(p[off:], d.frags[i].data)
				if d.frags[i].release != nil {
					d.frags[i].release()
					d.frags[i].release = nil
				}
				d.frags[i].data = nil
			}
			return off, true
		}
	} else {
		// Duplicate fragment: release the current buffer.
		if m.Release != nil {
			m.Release()
		}
	}
	return 0, false
}

func (d *Defragger) Close() error {
	d.releaseAll()
	return nil
}
