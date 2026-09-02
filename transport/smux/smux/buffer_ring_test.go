package smux

import (
	"testing"

	"github.com/daeuniverse/outbound/pool"
)

// TestBufferRingRecycleCap locks down the load-bearing invariant of the head
// mechanism: bufferRing.consumeFront reslices the working copy as data is
// consumed (shrinking its cap), but the *[]byte head keeps the original
// power-of-2 capacity — which is exactly what pool.PutBuffer requires to
// recycle the buffer instead of silently dropping it.
func TestBufferRingRecycleCap(t *testing.T) {
	const payload = 3000 // rounds up to the 4096 size class
	const class = 1 << 12

	r := newBufferRing(8)
	buf := pool.GetBuffer(payload)
	if cap(buf) != class {
		t.Fatalf("GetBuffer(%d) cap = %d, want %d", payload, cap(buf), class)
	}
	head := &buf
	r.push(*head, head)

	// Partial consumption must not recycle and must reslice the working copy.
	n, recycled := r.consumeFront(make([]byte, 1000))
	if n != 1000 || recycled != nil {
		t.Fatalf("partial consume: n = %d, recycled = %v; want n = 1000, recycled = nil", n, recycled)
	}
	if cap(r.bufs[r.head]) == class {
		t.Fatalf("working copy was not resliced: cap still %d", class)
	}

	// Full exhaustion recycles the head with the original class capacity.
	n, recycled = r.consumeFront(make([]byte, payload-1000))
	if n != payload-1000 || recycled == nil {
		t.Fatalf("exhausting consume: n = %d, recycled = %v; want n = %d, recycled = head", n, recycled, payload-1000)
	}
	if recycled != head {
		t.Fatalf("recycled = %p, want the original head %p", recycled, head)
	}
	if cap(*recycled) != class {
		t.Fatalf("recycled cap = %d, want %d (power-of-2 class)", cap(*recycled), class)
	}

	// The recycled head passes pool.PutBuffer's cap gate: a follow-up
	// GetBuffer of the same class must come back with the full class
	// capacity, proving the buffer was accepted back into the pool.
	pool.PutBuffer(*recycled)
	b := pool.GetBuffer(payload)
	if cap(b) != class {
		t.Fatalf("GetBuffer after PutBuffer cap = %d, want %d", cap(b), class)
	}
	pool.PutBuffer(b)
}
