package coalesce

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

type coalesceRecConn struct {
	net.Conn
	writes  [][]byte
	failOn  int
	closed  bool
	wdCount int
}

func (r *coalesceRecConn) Write(p []byte) (int, error) {
	if r.failOn > 0 && len(r.writes)+1 == r.failOn {
		return 0, errors.New("injected")
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	r.writes = append(r.writes, cp)
	return len(p), nil
}

func (r *coalesceRecConn) Close() error { r.closed = true; return nil }

func (r *coalesceRecConn) SetWriteDeadline(t time.Time) error { r.wdCount++; return nil }

func TestCoalesceMergesBurstIntoOneWrite(t *testing.T) {
	rec := &coalesceRecConn{}
	c := New(rec)
	if _, err := c.Write([]byte("record-one--")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("record-two--")); err != nil {
		t.Fatal(err)
	}
	if n := c.Pending(); n != 24 {
		t.Fatalf("pending = %d, want 24", n)
	}
	if len(rec.writes) != 0 {
		t.Fatalf("premature writes: %d", len(rec.writes))
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 1 {
		t.Fatalf("writes = %d, want 1 merged write", len(rec.writes))
	}
	if got := string(rec.writes[0]); got != "record-one--record-two--" {
		t.Fatalf("merged = %q", got)
	}
	if c.Pending() != 0 {
		t.Fatalf("pending after flush = %d", c.Pending())
	}
}

func TestCoalesceFlushEmptyIsNoop(t *testing.T) {
	rec := &coalesceRecConn{}
	c := New(rec)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 0 {
		t.Fatalf("unexpected writes: %d", len(rec.writes))
	}
}

func TestCoalesceDeadlineExpiredFailsFlush(t *testing.T) {
	rec := &coalesceRecConn{}
	c := New(rec)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Second)
	if err := c.SetWriteDeadline(past); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("flush err = %v, want deadline exceeded", err)
	}
	if c.Pending() != 0 {
		t.Fatalf("pending after failed flush = %d", c.Pending())
	}
	if len(rec.writes) != 0 {
		t.Fatalf("should not write past deadline, writes = %d", len(rec.writes))
	}
}

func TestCoalesceFlushPropagatesWriteError(t *testing.T) {
	rec := &coalesceRecConn{failOn: 1}
	c := New(rec)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err == nil || err.Error() != "injected" {
		t.Fatalf("flush err = %v, want injected", err)
	}
	if c.Pending() != 0 {
		t.Fatalf("buffer must be dropped after error, pending = %d", c.Pending())
	}
}

func TestCoalesceCloseClosesRawWithoutDrain(t *testing.T) {
	rec := &coalesceRecConn{}
	c := New(rec)
	if _, err := c.Write([]byte("close_notify")); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// Close deliberately does NOT drain: a flush blocked mid-write holds
	// mu, and draining first would deadlock the deadline escape hatches
	// that call Close. The contract is raw close, pending bytes dropped.
	if len(rec.writes) != 0 {
		t.Fatalf("pending bytes were flushed on Close: %+v", rec.writes)
	}
	if !rec.closed {
		t.Fatal("underlying conn not closed")
	}
}

func TestCoalesceHardLimitSelfFlushes(t *testing.T) {
	rec := &coalesceRecConn{}
	c := New(rec)
	chunk := make([]byte, 40<<10)
	for i := 0; i < 4; i++ { // 160KB total, crosses the 128KB limit
		if _, err := c.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.writes) == 0 {
		t.Fatal("hard limit did not trigger a self-flush")
	}
	if c.Pending() >= bufHardLimit {
		t.Fatalf("pending = %d still above limit", c.Pending())
	}
}

// TestCloseNotDeadlockedByBlockedFlush reproduces the deadlock escape: with
// a synchronous pipe whose peer never reads, a Read-triggered flush blocks
// mid-write holding mu. Close must still return promptly (deadline escape
// hatches wait on it), not queue behind the blocked flush forever.
func TestCloseNotDeadlockedByBlockedFlush(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c := New(client)
	// Accumulate more than the pipe buffers (net.Pipe is unbuffered, so
	// any record blocks until the peer reads; the peer never does).
	if _, err := c.Write(make([]byte, 4096)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		// Read flushes first and blocks on the pipe write.
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
	}()
	time.Sleep(20 * time.Millisecond) // let the read-side flush block
	go func() {
		done <- c.Close()
	}()
	select {
	case <-done:
		if time.Since(start) > time.Second {
			t.Fatalf("Close() took %v, want deadline-bounded return", time.Since(start))
		}
		// The flush failure may or may not surface from Close (a
		// deadline-class drain loss is deliberately swallowed); what
		// matters is that Close returned within the bound.
	case <-time.After(2 * time.Second):
		t.Fatal("Close() deadlocked behind a blocked flush")
	}
}

// TestCoalescePooledBufferRecycled verifies the pooled backing storage: after a
// Flush the buffer goes back to the pool, the next burst re-arms from a pooled
// slice, and bursts larger than the current capacity swap to a bigger
// power-of-2 pooled buffer without ever append-growing a pooled slice (which
// would break pool.PutBuffer's power-of-2 cap contract).
func TestCoalescePooledBufferRecycled(t *testing.T) {
	raw := &halfCloseConn{}
	co := New(raw)

	// First burst: lazily arms a pooled buffer.
	if _, err := co.Write(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	if err := co.Flush(); err != nil {
		t.Fatal(err)
	}

	// Second burst after flush: must re-arm cleanly and merge again.
	if _, err := co.Write(make([]byte, 4000)); err != nil {
		t.Fatal(err)
	}
	// Third write crossing the current capacity: must swap, not append-grow.
	if _, err := co.Write(make([]byte, 40000)); err != nil {
		t.Fatal(err)
	}
	if err := co.Flush(); err != nil {
		t.Fatal(err)
	}
	var got int
	for _, w := range raw.writes {
		got += len(w)
	}
	if got != 1000+4000+40000 {
		t.Fatalf("flushed %d bytes, want %d", got, 1000+4000+40000)
	}

	// Error-path flush (expired deadline) must also release the buffer.
	_ = co.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := co.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	if err := co.Flush(); err != os.ErrDeadlineExceeded {
		t.Fatalf("Flush err = %v, want ErrDeadlineExceeded", err)
	}
	// The dropped bytes must not reappear in a later flush.
	_ = co.SetWriteDeadline(time.Time{})
	if err := co.Flush(); err != nil {
		t.Fatal(err)
	}
	var after int
	for _, w := range raw.writes {
		after += len(w)
	}
	if after != got {
		t.Fatalf("dropped bytes leaked into a later flush: %d -> %d", got, after)
	}
}
