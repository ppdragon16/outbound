package frag

import (
	"sync"
	"time"

	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

func FragUDPMessage(m protocol.UDPMessage, maxSize int) []protocol.UDPMessage {
	if m.Size() <= maxSize {
		return []protocol.UDPMessage{m}
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
		frag := m
		frag.FragID = fragID
		frag.FragCount = fragCount
		frag.Data = fullPayload[off : off+payloadSize]
		frags[fragID] = frag
		off += payloadSize
		fragID++
	}
	return frags
}

// fragPiece holds a fragment's data sub-slice together with the full-cap
// datagram buffer (DataBuf). The full-cap buffer is needed because
// quic-go's ReleaseDatagram checks cap(buf) == MaxPacketBufferSize,
// which fails on sub-slices.
type fragPiece struct {
	data []byte
	buf  []byte // full-cap buffer from quic-go's ReceiveDatagram
}

// defragInlineSize is the number of fragment slots stored inline. A QUIC
// datagram (~1.2-1.5 KB payload) splits into 2 fragments in the common case,
// and MaxUDPSize (4 KB) needs at most ~4, so 8 inline slots cover it without
// a per-packet heap allocation on the hot path.
const defragInlineSize = 8

var defraggerPool = sync.Pool{
	New: func() any { return &Defragger{} },
}

// Defragger reassembles one fragmented UDP message (a single PacketID) from
// its fragments. The caller keeps one Defragger per in-flight PacketID; reuse
// it via GetDefragger/Put to avoid per-packet allocations.
type Defragger struct {
	pktID     uint16
	frags     []fragPiece
	count     uint8
	ReleaseFn func([]byte) // injected by caller: releases a quic-go datagram buffer

	// closed is set once Put/Close has run. A delayed Feed arriving after
	// release must not repopulate reassembly state: the session is gone, so
	// nothing will ever call releaseAll again and the buffer would otherwise
	// be retained until the Defragger is garbage collected.
	closed bool

	// inline backs frags for FRAG_TOTAL <= defragInlineSize, avoiding a heap
	// allocation on the hot path.
	inline [defragInlineSize]fragPiece

	// ExpiresAt is when an incomplete reassembly is abandoned (a fragment was
	// lost and never arrived). Managed by the caller for lost-fragment cleanup.
	ExpiresAt time.Time
}

// GetDefragger returns a reset Defragger from the pool with releaseFn wired.
func GetDefragger(releaseFn func([]byte)) *Defragger {
	d := defraggerPool.Get().(*Defragger)
	d.pktID = 0
	d.frags = nil
	d.count = 0
	d.closed = false
	d.ReleaseFn = releaseFn
	d.ExpiresAt = time.Time{}
	for i := range d.inline {
		d.inline[i] = fragPiece{}
	}
	return d
}

// Put releases any held fragment buffers and returns d to the pool.
func (d *Defragger) Put() {
	d.releaseAll()
	d.closed = true
	d.ReleaseFn = nil
	d.ExpiresAt = time.Time{}
	defraggerPool.Put(d)
}

// releaseAll calls ReleaseFn on every stored full-cap buffer and resets the
// reassembly state. Safe to call when no fragments are stored.
func (d *Defragger) releaseAll() {
	for i := range d.frags {
		if d.frags[i].buf != nil {
			d.ReleaseFn(d.frags[i].buf)
			d.frags[i].buf = nil
		}
		d.frags[i].data = nil
	}
	d.frags = nil
	d.count = 0
	for i := range d.inline {
		d.inline[i] = fragPiece{}
	}
}

func (d *Defragger) Feed(m *protocol.UDPMessage, p []byte) (int, bool) {
	if d.closed {
		// Terminal: release the incoming buffer and refuse to reassemble.
		if d.ReleaseFn != nil && m.DataBuf != nil {
			d.ReleaseFn(m.DataBuf)
		}
		m.DataBuf = nil
		return 0, false
	}
	if m.FragCount <= 1 {
		// Single fragment: release the buffer immediately.
		n := copy(p, m.Data)
		if d.ReleaseFn != nil && m.DataBuf != nil {
			d.ReleaseFn(m.DataBuf)
		}
		m.DataBuf = nil
		return n, true
	}
	if m.FragID >= m.FragCount {
		// Invalid fragment ID: release the current buffer.
		if d.ReleaseFn != nil && m.DataBuf != nil {
			d.ReleaseFn(m.DataBuf)
		}
		m.DataBuf = nil
		return 0, false
	}
	if m.PacketID != d.pktID || m.FragCount != uint8(len(d.frags)) {
		// New packet: release previously held fragments before overwriting.
		d.releaseAll()
		d.pktID = m.PacketID
		if int(m.FragCount) <= defragInlineSize {
			d.frags = d.inline[:m.FragCount]
		} else {
			d.frags = make([]fragPiece, m.FragCount)
		}
		d.frags[m.FragID] = fragPiece{data: m.Data, buf: m.DataBuf}
		m.DataBuf = nil
		d.count = 1
	} else if d.frags[m.FragID].data == nil {
		d.frags[m.FragID] = fragPiece{data: m.Data, buf: m.DataBuf}
		m.DataBuf = nil
		d.count++
		if int(d.count) == len(d.frags) {
			// all fragments received, assemble and release
			off := 0
			for i := range d.frags {
				off += copy(p[off:], d.frags[i].data)
				if d.frags[i].buf != nil {
					d.ReleaseFn(d.frags[i].buf)
					d.frags[i].buf = nil
				}
				d.frags[i].data = nil
			}
			return off, true
		}
	} else {
		// Duplicate fragment: release the current buffer.
		if d.ReleaseFn != nil && m.DataBuf != nil {
			d.ReleaseFn(m.DataBuf)
		}
		m.DataBuf = nil
	}
	return 0, false
}

func (d *Defragger) Close() error {
	d.closed = true
	d.releaseAll()
	return nil
}
