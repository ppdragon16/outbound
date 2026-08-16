package bbr

import "testing"

func TestRingBufferShrinkPreservesElements(t *testing.T) {
	var r RingBuffer[int]
	r.Init(4)

	// Grow to 16 via a burst, exercising the wrap-around path.
	// 4 -> 8 -> 16.
	for i := 0; i < 15; i++ {
		r.PushBack(i)
	}
	if got := len(r.ring); got != 16 {
		t.Fatalf("expected ring capacity 16 after burst, got %d", got)
	}

	// Pop down to 3 live elements (wrap around past headPos multiple times).
	for i := 0; i < 12; i++ {
		r.PopFront()
	}
	if got := r.Len(); got != 3 {
		t.Fatalf("expected 3 live elements, got %d", got)
	}

	// 3 out of 16 -> under a quarter full, so shrink should halve to 8.
	if !r.ShrinkIfUnderutilized() {
		t.Fatal("expected shrink to happen when under a quarter full")
	}
	if got := len(r.ring); got != 8 {
		t.Fatalf("expected capacity 8 after shrink, got %d", got)
	}

	// Elements must be preserved in order (12, 13, 14).
	want := []int{12, 13, 14}
	for i, w := range want {
		if got := r.Offset(i); *got != w {
			t.Fatalf("element %d = %d, want %d", i, *got, w)
		}
	}
	if r.full {
		t.Fatal("ring should not be full after shrink")
	}
}

func TestRingBufferShrinkDoesNotDropBelowMin(t *testing.T) {
	var r RingBuffer[int]
	r.Init(4)
	for i := 0; i < 20; i++ {
		r.PushBack(i)
	}
	// Fully drain.
	for !r.Empty() {
		r.PopFront()
	}
	// Empty ring shrinks repeatedly, but never below minSize (4).
	for i := 0; i < 10; i++ {
		r.ShrinkIfUnderutilized()
	}
	if got := len(r.ring); got != 4 {
		t.Fatalf("expected capacity to stay at min 4, got %d", got)
	}
}

func TestRingBufferShrinkNoOpWhenAboveQuarter(t *testing.T) {
	var r RingBuffer[int]
	r.Init(4)
	for i := 0; i < 16; i++ {
		r.PushBack(i)
	}
	for i := 0; i < 8; i++ {
		r.PopFront()
	}
	// 8 out of 16 live -> exactly half, no shrink.
	if r.ShrinkIfUnderutilized() {
		t.Fatal("expected no shrink when half full")
	}
	if got := len(r.ring); got != 16 {
		t.Fatalf("expected capacity 16, got %d", got)
	}
}
