package client

import (
	"context"
	"encoding/binary"
	"testing"
)

// BenchmarkUDPDemuxFeed measures the per-datagram cost of the session
// manager's demux goroutine: the session-id read, the connMap lookup and
// the handoff to the session's receive channel (with a draining consumer).
// Parsing and defragmentation are NOT part of this path - they run in each
// association's own reader goroutine.
func BenchmarkUDPDemuxFeed(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &fakeSendConn{entered: make(chan struct{})}
	sm := &udpSessionManager{conn: conn, ctx: ctx, cancel: cancel}
	const sessions = 64
	for i := 0; i < sessions; i++ {
		u := &udpConn{
			ID:        uint32(i + 1),
			ReceiveCh: make(chan []byte, 128),
			conn:      conn,
			sm:        sm,
			ctx:       ctx,
			cancel:    cancel,
		}
		sm.connMap.Store(u.ID, u)
		go func(u *udpConn) {
			for range u.ReceiveCh {
			}
		}(u)
	}
	datagrams := make([][]byte, sessions)
	for i := range datagrams {
		d := make([]byte, 64)
		binary.BigEndian.PutUint32(d, uint32(i+1))
		datagrams[i] = d
	}
	b.SetBytes(64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.feed(datagrams[i%sessions])
	}
}
