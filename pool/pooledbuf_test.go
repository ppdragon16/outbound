package pool

import (
	"bytes"
	"strings"
	"testing"
)

func TestSoftResetGrowReusesBuffer(t *testing.T) {
	b := NewPooledBuffer()

	// Write data to grow the buffer beyond initial capacity.
	data := strings.Repeat("x", 4096)
	b.Write([]byte(data))
	initialCap := cap(b.buf)
	// Consume all data via Next to trigger off > 0, len = off.
	b.Next(len(data))
	if b.Len() != 0 {
		t.Fatalf("expected Len()==0 after consuming all data, got %d", b.Len())
	}
	if b.off == 0 {
		t.Fatal("expected off > 0 after consuming all data")
	}

	// Grow with the buffer in the Len()==0 && off!=0 state.
	// This should soft-reset and reuse the backing array.
	b.Grow(512)
	if cap(b.buf) != initialCap {
		t.Fatalf("expected buffer to be reused (cap %d), but got cap %d", initialCap, cap(b.buf))
	}
	if b.off != 0 {
		t.Fatalf("expected off==0 after soft-reset grow, got %d", b.off)
	}
	if b.Len() != 0 {
		t.Fatalf("expected Len()==0 after soft-reset grow, got %d", b.Len())
	}
}

func TestSoftResetAfterReadFrom(t *testing.T) {
	b := NewPooledBuffer()

	// ReadFrom with a large reader to fill the buffer.
	r := strings.NewReader(strings.Repeat("x", 8192))
	n, err := b.ReadFrom(r)
	if err != nil {
		t.Fatal(err)
	}
	if n != 8192 {
		t.Fatalf("expected 8192 bytes read, got %d", n)
	}
	initialCap := cap(b.buf)

	// Consume all data.
	b.Next(int(n))
	if b.Len() != 0 {
		t.Fatal("expected Len()==0 after consuming all data")
	}

	// Grow should reuse the buffer.
	b.Grow(256)
	if cap(b.buf) != initialCap {
		t.Fatalf("expected buffer reuse (cap %d), got cap %d", initialCap, cap(b.buf))
	}
}

func TestExplicitResetStillPutsBuffer(t *testing.T) {
	b := NewPooledBuffer()
	b.Write([]byte("hello"))
	c := cap(b.buf)
	if c == 0 {
		t.Fatal("expected buffer to have capacity after write")
	}

	b.Reset()
	if b.buf != nil {
		t.Fatal("expected buf to be nil after explicit Reset")
	}
	if cap(b.buf) != 0 {
		t.Fatal("expected cap 0 after explicit Reset")
	}
}

func TestWriteAfterSoftResetPreservesIntegrity(t *testing.T) {
	b := NewPooledBuffer()

	// First write.
	b.Write([]byte("first data"))
	// Consume all.
	b.Next(len("first data"))
	// Soft-reset via Grow.
	b.Grow(64)
	// Write new data.
	b.Write([]byte("second data"))
	// Consume and verify.
	result := string(b.Bytes())
	if result != "second data" {
		t.Fatalf("expected 'second data', got '%s'", result)
	}
}

func TestMultipleConsumeGrowCycles(t *testing.T) {
	b := NewPooledBuffer()

	for i := 0; i < 100; i++ {
		payload := strings.Repeat("a", 1024)
		b.Write([]byte(payload))
		if b.Len() != 1024 {
			t.Fatalf("iteration %d: expected Len %d, got %d", i, 1024, b.Len())
		}
		// Consume all.
		consumed := b.Next(b.Len())
		if len(consumed) != 1024 {
			t.Fatalf("iteration %d: expected consumed %d, got %d", i, 1024, len(consumed))
		}
		// Soft-reset.
		b.Grow(128)
		if b.Len() != 0 || b.off != 0 {
			t.Fatalf("iteration %d: expected Len==0 && off==0 after grow, got Len=%d off=%d", i, b.Len(), b.off)
		}
	}
}

func TestSoftResetWhenBufferHasRemainingData(t *testing.T) {
	b := NewPooledBuffer()
	b.Write([]byte(strings.Repeat("x", 1024)))

	// Consume only half.
	b.Next(512)
	if b.Len() == 0 {
		t.Fatal("expected Len() > 0 after partial consume")
	}

	// Grow with remaining data should NOT soft-reset; it should shift data.
	b.Grow(256)
	if b.off != 0 {
		t.Fatalf("expected off==0 after grow with remaining data, got %d", b.off)
	}
	remaining := b.Bytes()
	if len(remaining) != 512 {
		t.Fatalf("expected 512 bytes remaining after grow, got %d", len(remaining))
	}
}

func TestSoftResetDoesNotLeakOldData(t *testing.T) {
	b := NewPooledBuffer()

	// Write old data and consume it.
	oldData := strings.Repeat("OLD", 1024)
	b.Write([]byte(oldData))
	b.Next(len(oldData))

	// Soft-reset.
	b.Grow(64)

	// Write new smaller data.
	b.Write([]byte("new"))
	if b.Len() != 3 {
		t.Fatalf("expected Len 3, got %d", b.Len())
	}

	// Verify Bytes returns only new data (not old residual).
	result := string(b.Bytes())
	if result != "new" {
		t.Fatalf("expected 'new', got '%s'", result)
	}
}

func TestGrowNoAllocWhenCapacitySufficient(t *testing.T) {
	b := NewPooledBuffer()

	// Pre-grow to a known capacity.
	b.Grow(8192)
	initialCap := cap(b.buf)

	// Consume some data we wrote, then empty.
	// Since we only Grew (no Write), Len() is 0 and off is 0.
	// Write data and consume it.
	b.Write([]byte(strings.Repeat("x", 4096)))
	b.Next(4096)

	// Soft-reset: now we have a buffer with off>0 and len==0 but cap==8192+.
	b.Grow(512)
	if cap(b.buf) != initialCap {
		t.Fatalf("expected same cap %d, got %d", initialCap, cap(b.buf))
	}
}

func TestPooledBufferWriteTo(t *testing.T) {
	b := NewPooledBuffer()
	b.WriteString("hello world")

	var dst bytes.Buffer
	n, err := b.WriteTo(&dst)
	if err != nil {
		t.Fatal(err)
	}
	if n != 11 {
		t.Fatalf("n = %d, want 11", n)
	}
	if dst.String() != "hello world" {
		t.Fatalf("dst = %q, want %q", dst.String(), "hello world")
	}
	if b.Len() != 0 {
		t.Fatalf("buffer not reset after WriteTo: Len = %d", b.Len())
	}
}
