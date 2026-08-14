package pool

import (
	"math/bits"
	"testing"
	"time"
)

func classIndex(size int) int { return bits.Len32(uint32(size - 1)) }

// resetClass empties a class pool so tests start from a clean slate.
func resetClass(i int) {
	p := &classPools[i]
	p.mu.Lock()
	for p.n > 0 {
		p.buf[p.head] = bufEntry{}
		p.head = (p.head + 1) & p.mask
		p.n--
	}
	p.mu.Unlock()
}

// TestClassPoolByteBudget verifies a class pool holds at most bucketMax(class)
// buffers and the overflow falls back to sync.Pool (not the bounded ring).
func TestClassPoolByteBudget(t *testing.T) {
	const class = 2048
	i := classIndex(class)
	p := &classPools[i]
	if p.max != bucketMax(class) {
		t.Fatalf("max = %d, want %d", p.max, bucketMax(class))
	}
	resetClass(i)

	// Hold distinct buffers so PutBuffer cannot just recycle the same one.
	bufs := make([][]byte, p.max+10)
	for n := range bufs {
		bufs[n] = make([]byte, class)
	}
	for _, b := range bufs {
		PutBuffer(b)
	}
	if got := p.n; got != p.max {
		t.Fatalf("class pool held %d buffers, want %d", got, p.max)
	}
	resetClass(i)
}

// TestClassPoolFIFO verifies buffers are returned in insertion order.
func TestClassPoolFIFO(t *testing.T) {
	const class = 2048
	i := classIndex(class)
	resetClass(i)

	a, b := GetBuffer(class), GetBuffer(class)
	a[0], b[0] = 'a', 'b'
	PutBuffer(a)
	PutBuffer(b)

	if got := GetBuffer(class); got[0] != 'a' {
		t.Fatalf("FIFO: first buffer byte = %q, want 'a'", got[0])
	}
	if got := GetBuffer(class); got[0] != 'b' {
		t.Fatalf("FIFO: second buffer byte = %q, want 'b'", got[0])
	}
	resetClass(i)
}

// TestClassPoolGetReusesExpired verifies get returns a buffer even if it has sat
// idle past the TTL — reuse wins over release on the get path; only the sweeper
// releases idle memory.
func TestClassPoolGetReusesExpired(t *testing.T) {
	const class = 2048
	i := classIndex(class)
	resetClass(i)

	PutBuffer(make([]byte, class))
	p := &classPools[i]
	p.mu.Lock()
	if p.n != 1 {
		p.mu.Unlock()
		t.Fatalf("expected 1 buffered entry, got %d", p.n)
	}
	p.buf[p.head].putTime = time.Now().Add(-2 * bucketTTL)
	p.mu.Unlock()

	if got := p.get(class, class); got == nil {
		t.Fatal("expected expired buffer to be reused, got nil")
	}
	if p.n != 0 {
		t.Fatalf("expected pool empty after get, got %d entries", p.n)
	}
}

// TestClassPoolPutReusesExpiredHead verifies a full ring whose head is expired
// accepts the next put by overwriting that head slot instead of falling back.
func TestClassPoolPutReusesExpiredHead(t *testing.T) {
	const class = 2048
	i := classIndex(class)
	resetClass(i)

	p := &classPools[i]
	for n := 0; n < p.max; n++ {
		PutBuffer(make([]byte, class))
	}
	if p.n != p.max {
		t.Fatalf("ring not full: n=%d max=%d", p.n, p.max)
	}

	p.mu.Lock()
	oldHead := p.head
	p.buf[p.head].putTime = time.Now().Add(-2 * bucketTTL)
	p.mu.Unlock()

	PutBuffer(make([]byte, class))
	if p.n != p.max {
		t.Fatalf("ring size changed after put: n=%d want %d", p.n, p.max)
	}
	if p.head != (oldHead+1)&p.mask {
		t.Fatalf("head did not advance past the expired slot: got %d want %d", p.head, (oldHead+1)&p.mask)
	}
	resetClass(i)
}

// TestGetBufferClassSized verifies a non-power-of-2 request still gets a
// class-sized (power-of-2) buffer that PutBuffer pools back.
func TestGetBufferClassSized(t *testing.T) {
	i := classIndex(2048)
	resetClass(i)

	b := GetBuffer(1500)
	if cap(b) != 2048 {
		t.Fatalf("GetBuffer(1500) cap = %d, want 2048 (class size)", cap(b))
	}
	PutBuffer(b)
	if classPools[i].n == 0 {
		t.Fatal("GetBuffer(1500) buffer was not pooled into the 2048 bucket")
	}
	resetClass(i)
}

// TestClassPoolRingReuse verifies the ring reuses its fixed backing array across
// repeated put/get cycles instead of reallocating (the head-drift regression).
func TestClassPoolRingReuse(t *testing.T) {
	const class = 2048
	i := classIndex(class)
	resetClass(i)

	// Drain-to-empty on every cycle: this is the pattern that would make a
	// slice queue reallocate its backing array on every put.
	b := GetBuffer(class)
	PutBuffer(b)
	p := &classPools[i]
	if p.buf == nil || len(p.buf) != p.max {
		t.Fatalf("ring not allocated to max on first put: len(buf)=%d, max=%d", len(p.buf), p.max)
	}

	for range 1000 {
		got := GetBuffer(class)
		got[0] = 'x'
		PutBuffer(got)
	}
	if len(p.buf) != p.max {
		t.Fatalf("ring backing array changed size after churn: len(buf)=%d, max=%d", len(p.buf), p.max)
	}
	if p.n != 1 {
		t.Fatalf("ring held %d live entries after churn, want 1", p.n)
	}
	resetClass(i)
}

// TestPoolStatsOccupancy verifies PoolStats reports a class's current ring fill
// and its capacity.
func TestPoolStatsOccupancy(t *testing.T) {
	const class = 2048
	i := classIndex(class)
	resetClass(i)

	p := &classPools[i]
	for n := 0; n < 3; n++ {
		PutBuffer(make([]byte, class))
	}
	var snap StatsSnapshot
	PoolStats(&snap)
	s := snap[i]
	if s.Occupancy != 3 || s.Max != p.max {
		t.Fatalf("Occupancy=%d Max=%d, want 3 / %d", s.Occupancy, s.Max, p.max)
	}
	resetClass(i)
}

// TestPoolStatsHitRate verifies a ring hit increments Gets and RingHit but not
// Alloc — the counters behind HitRate/RingHitRate.
func TestPoolStatsHitRate(t *testing.T) {
	const class = 2048
	i := classIndex(class)
	resetClass(i)

	var snap StatsSnapshot
	PoolStats(&snap)
	before := snap[i]
	PutBuffer(make([]byte, class)) // ring now holds one buffer
	GetBuffer(class)               // served from the ring
	PoolStats(&snap)
	after := snap[i]

	if after.Gets != before.Gets+1 {
		t.Fatalf("Gets = %d, want %d", after.Gets, before.Gets+1)
	}
	if after.RingHit != before.RingHit+1 {
		t.Fatalf("RingHit = %d, want %d", after.RingHit, before.RingHit+1)
	}
	if after.Alloc != before.Alloc {
		t.Fatalf("Alloc changed on a ring hit: %d -> %d", before.Alloc, after.Alloc)
	}
	resetClass(i)
}

// TestGetBufferAllocOnColdMiss verifies a cold miss (empty ring and empty
// sync.Pool) increments Alloc and returns a class-sized buffer. This guards
// against the regression where sync.Pool.New made Get never return nil, so the
// alloc counter was unreachable and always zero.
func TestGetBufferAllocOnColdMiss(t *testing.T) {
	const class = 2048
	i := classIndex(class)
	resetClass(i)
	for pools[i].Get() != nil { // drain the sync.Pool fallback
	}

	var snap StatsSnapshot
	PoolStats(&snap)
	before := snap[i].Alloc
	b := GetBuffer(class)
	PoolStats(&snap)
	after := snap[i].Alloc
	if after != before+1 {
		t.Fatalf("Alloc = %d, want %d", after, before+1)
	}
	if cap(b) != class {
		t.Fatalf("cap = %d, want %d (class-sized on miss)", cap(b), class)
	}
	resetClass(i)
}

// TestTinyClassBypassesRing verifies buffers <= smallClassSize are served by
// sync.Pool directly and never allocate or populate the GC-surviving ring.
func TestTinyClassBypassesRing(t *testing.T) {
	const class = 16
	i := classIndex(class)
	resetClass(i)

	b := GetBuffer(class)
	PutBuffer(b)
	if classPools[i].n != 0 {
		t.Fatalf("tiny class %d should bypass the ring, got n=%d", class, classPools[i].n)
	}
	if classPools[i].buf != nil {
		t.Fatalf("tiny class %d should not allocate a ring", class)
	}
	resetClass(i)
}
