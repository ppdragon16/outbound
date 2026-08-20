package smux

import "testing"

func mkWriteRequest(sid uint32) writeRequest {
	return writeRequest{
		class:  CLSDATA,
		frame:  Frame{sid: sid},
		result: make(chan writeResult, 1),
	}
}

func TestShaperQueueRoundRobin(t *testing.T) {
	sq := NewShaperQueue()
	sq.Push(mkWriteRequest(1))
	sq.Push(mkWriteRequest(1))
	sq.Push(mkWriteRequest(2))
	sq.Push(mkWriteRequest(3))

	if sq.Len() != 4 {
		t.Fatalf("Len() = %d, want 4", sq.Len())
	}

	// Expect round-robin: 1, 2, 3, then the second request of sid 1.
	want := []uint32{1, 2, 3, 1}
	for i, w := range want {
		req, ok := sq.Pop()
		if !ok {
			t.Fatalf("Pop() #%d not ok", i)
		}
		if req.frame.sid != w {
			t.Fatalf("Pop() #%d = sid %d, want %d", i, req.frame.sid, w)
		}
	}

	if !sq.IsEmpty() {
		t.Fatal("IsEmpty() = false, want true")
	}
	if _, ok := sq.Pop(); ok {
		t.Fatal("Pop() on empty returned ok")
	}
}

func TestShaperQueueDrainMany(t *testing.T) {
	sq := NewShaperQueue()
	const n = 1000
	for sid := uint32(1); sid <= n; sid++ {
		sq.Push(mkWriteRequest(sid))
	}

	seen := make(map[uint32]bool, n)
	for i := 0; i < n; i++ {
		req, ok := sq.Pop()
		if !ok {
			t.Fatalf("Pop() #%d not ok", i)
		}
		if seen[req.frame.sid] {
			t.Fatalf("sid %d popped twice", req.frame.sid)
		}
		seen[req.frame.sid] = true
	}

	if !sq.IsEmpty() {
		t.Fatal("IsEmpty() = false after draining")
	}
	if _, ok := sq.Pop(); ok {
		t.Fatal("Pop() on empty returned ok")
	}
}
