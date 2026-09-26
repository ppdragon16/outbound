package smux

import (
	"io"

	"github.com/daeuniverse/outbound/pool"
)

const (
	// minFrameReadBufferSize is the recvLoop read buffer's starting size:
	// enough to absorb a burst of small frames without a syscall per frame,
	// cheap enough that an idle session commits almost nothing.
	minFrameReadBufferSize = 2 << 10
	// maxFrameReadBufferSize caps the adaptive growth (see frameReader).
	maxFrameReadBufferSize = 32 << 10
)

// frameReader is recvLoop's buffered reader. It exists because bufio's
// buffer is fixed at construction and cannot grow, while the right size
// depends on the session's live burstiness: an idle control session is fine
// with 2KiB, a QUIC-video session absorbing multi-frame TCP segments wants
// as much as 32KiB.
//
// Growth policy mirrors the relay loop's: whenever a fill consumed the
// entire buffer (i.e. the kernel had at least cap bytes ready - evidence
// the working set exceeds our capacity), the buffer doubles, up to the cap.
// Shrinkage is deliberately not implemented: sessions that were busy once
// tend to be busy again, and the cap bounds the cost.
//
// Like bufio, large reads that fit the caller's slice bypass the buffer
// with a single syscall straight into it (no copy, no growth signal).
//
// The session's recvLoop is the only reader of the session conn, so there
// is no concurrency to worry about.
type frameReader struct {
	conn io.Reader
	buf  []byte
	// start/end bracket the unconsumed span of buf left over from the last
	// fill (zero-width when empty).
	start, end   int
	lastFillFull bool
}

func newFrameReader(conn io.Reader) *frameReader {
	return &frameReader{conn: conn, buf: pool.GetBuffer(minFrameReadBufferSize)}
}

// release returns the buffer to the pool. Call exactly once when the reader
// is done - i.e. when recvLoop exits. The buffer is pooled rather than
// made because sessions churn (update-sub, reconnects) and recycled buffers
// let a new session skip the cold allocation; the lifetime discipline is
// simple because recvLoop is the only user.
func (r *frameReader) release() {
	pool.PutBuffer(r.buf)
	r.buf = nil
}

func (r *frameReader) Read(p []byte) (n int, err error) {
	// Serve from the leftover of the previous fill first.
	if r.start < r.end {
		n = copy(p, r.buf[r.start:r.end])
		r.start += n
		if r.start == r.end {
			r.start, r.end = 0, 0
		}
		return n, nil
	}
	if len(p) == 0 {
		return 0, nil
	}

	// Large reads bypass the buffer: one syscall straight into the caller's
	// slice, no copy, and no growth evidence (nothing was "held back").
	if len(p) >= len(r.buf) {
		r.lastFillFull = false
		return r.conn.Read(p)
	}

	// Grow only on evidence: the previous fill hit the buffer's exact
	// capacity, meaning at least that many bytes were waiting and we may
	// have left data in the kernel for a second syscall. The old buffer is
	// recycled back to the pool as part of the swap.
	if r.lastFillFull && len(r.buf) < maxFrameReadBufferSize {
		newSize := min(len(r.buf)*2, maxFrameReadBufferSize)
		pool.PutBuffer(r.buf)
		r.buf = pool.GetBuffer(newSize)
	}
	r.start, r.end = 0, 0
	n, err = r.conn.Read(r.buf)
	r.lastFillFull = n == len(r.buf)
	copied := copy(p, r.buf[:n])
	if copied < n {
		// Stash the bytes the caller had no room for; hand them out on the
		// next Read.
		r.start, r.end = copied, n
	}
	return copied, err
}
