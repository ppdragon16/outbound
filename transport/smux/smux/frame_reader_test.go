package smux

import (
	"bytes"
	"io"
	"testing"
)

// chunkReader delivers a fixed blob in chunks, recording the size of every
// read request it receives.
type chunkReader struct {
	data    []byte
	reqs    []int
	maxReq  int
	maxReqN int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	c.reqs = append(c.reqs, len(p))
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	if n > c.maxReqN {
		c.maxReqN = n
	}
	return n, nil
}

// The reader must start small, grow only on evidence of full fills, cap at
// maxFrameReadBufferSize, stash remainder bytes across Reads, and bypass
// the buffer for caller slices at least as large as the buffer.
func TestFrameReaderAdaptiveGrowthAndRemainder(t *testing.T) {
	// 8 frames of 1200B arriving in one kernel gulp: with a 2KiB start size
	// the first fill fills fully -> grow -> subsequent fills absorb more.
	blob := bytes.Repeat([]byte{0xAB}, 8*1200)
	cr := &chunkReader{data: append([]byte{}, blob...)}
	r := newFrameReader(cr)

	if len(r.buf) != minFrameReadBufferSize {
		t.Fatalf("initial buffer = %d, want %d", len(r.buf), minFrameReadBufferSize)
	}

	var got []byte
	var grownAt int
	for len(got) < len(blob) {
		capBefore := len(r.buf)
		p := make([]byte, 1200)
		n, err := r.Read(p)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		got = append(got, p[:n]...)
		if len(r.buf) > capBefore {
			grownAt = len(got)
		}
	}
	if !bytes.Equal(got, blob) {
		t.Fatal("streamed bytes mismatch")
	}
	if len(r.buf) == minFrameReadBufferSize {
		t.Fatal("buffer never grew despite sustained full fills")
	}
	if len(r.buf) > maxFrameReadBufferSize {
		t.Fatalf("buffer grew past cap: %d", len(r.buf))
	}
	if grownAt == 0 {
		t.Fatal("growth happened but was not observed")
	}

	// Bypass: a caller slice >= buffer capacity reads straight into it (the
	// recorded request len equals the slice size and the buffer stays put).
	cr2 := &chunkReader{data: bytes.Repeat([]byte{0xCD}, 40000)}
	r2 := newFrameReader(cr2)
	// Prime a full fill so lastFillFull is set, then drain the stash so the
	// buffer is empty.
	if _, err := r2.Read(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	if !r2.lastFillFull {
		t.Fatal("expected a full fill on first small read")
	}
	for r2.start < r2.end {
		if _, err := r2.Read(make([]byte, 700)); err != nil {
			t.Fatal(err)
		}
	}
	// Bypass: an empty buffer + caller slice >= buffer capacity reads
	// straight into the slice (one syscall, recorded request len equals the
	// slice size), leaves the buffer untouched, and does not count as
	// growth evidence.
	before := len(r2.buf)
	if _, err := r2.Read(make([]byte, maxFrameReadBufferSize)); err != nil {
		t.Fatal(err)
	}
	if got := cr2.reqs[len(cr2.reqs)-1]; got != maxFrameReadBufferSize {
		t.Fatalf("last read request = %d, want direct bypass of %d", got, maxFrameReadBufferSize)
	}
	if len(r2.buf) != before {
		t.Fatalf("bypass read grew the buffer: %d", len(r2.buf))
	}
	if r2.lastFillFull {
		t.Fatal("bypass read must not count as growth evidence")
	}
	_ = cr.maxReq
}
