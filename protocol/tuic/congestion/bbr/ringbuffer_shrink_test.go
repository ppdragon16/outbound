package bbr

import "testing"

func TestRingBufferShrinkIfEmpty(t *testing.T) {
	var r RingBuffer[int]
	r.Init(4)

	// Grow to 16 via a burst, exercising the wrap-around path.
	for i := 0; i < 15; i++ {
		r.PushBack(i)
	}
	if got := len(r.ring); got != 16 {
		t.Fatalf("expected ring capacity 16 after burst, got %d", got)
	}

	// Non-empty rings never shrink, even when well below capacity. This guards
	// against grow/shrink allocation thrash during active congestion control.
	if r.ShrinkIfEmpty() {
		t.Fatal("expected no shrink while elements are still present")
	}
	if got := len(r.ring); got != 16 {
		t.Fatalf("expected capacity 16, got %d", got)
	}

	// Drain fully, then shrink back to minSize.
	for !r.Empty() {
		r.PopFront()
	}
	if !r.ShrinkIfEmpty() {
		t.Fatal("expected shrink when empty")
	}
	if got := len(r.ring); got != 4 {
		t.Fatalf("expected capacity 4 after shrink, got %d", got)
	}
	if !r.Empty() {
		t.Fatal("ring should be empty after shrink")
	}

	// Idempotent: already at minSize, no further shrink.
	if r.ShrinkIfEmpty() {
		t.Fatal("expected no shrink at minSize")
	}
}

func TestRingBufferShrinkThenRegrow(t *testing.T) {
	var r RingBuffer[int]
	r.Init(4)
	for i := 0; i < 20; i++ {
		r.PushBack(i)
	}
	for !r.Empty() {
		r.PopFront()
	}
	if !r.ShrinkIfEmpty() {
		t.Fatal("expected shrink when empty")
	}
	// After shrinking, the ring must be fully functional again.
	for i := 100; i < 110; i++ {
		r.PushBack(i)
	}
	for i := 100; i < 110; i++ {
		if got := r.PopFront(); got != i {
			t.Fatalf("PopFront = %d, want %d", got, i)
		}
	}
}
