package pool

import (
	"math/bits"
	"strings"
	"testing"
	"time"
)

func classIndex(size int) int { return bits.Len32(uint32(size - 1)) }

// resetClass empties a class pool and shrinks its ring back to the initial
// size, so tests start from a clean slate.
func resetClass(i int) {
	p := &classPools[i]
	p.mu.Lock()
	p.buf = nil
	p.head = 0
	p.n = 0
	p.cap = min(initialRingSize, p.max)
	p.mask = p.cap - 1
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

// TestClassPoolLIFO verifies buffers are returned in most-recent-first order.
func TestClassPoolLIFO(t *testing.T) {
	const class = 2048
	i := classIndex(class)
	resetClass(i)

	a, b := GetBuffer(class), GetBuffer(class)
	a[0], b[0] = 'a', 'b'
	PutBuffer(a)
	PutBuffer(b)

	if got := GetBuffer(class); got[0] != 'b' {
		t.Fatalf("LIFO: first buffer byte = %q, want 'b'", got[0])
	}
	if got := GetBuffer(class); got[0] != 'a' {
		t.Fatalf("LIFO: second buffer byte = %q, want 'a'", got[0])
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
	const class = 32768 // big class: still on the fast bucketTTL decay
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

	before := p.demoted.Load()
	PutBuffer(make([]byte, class))
	if p.n != p.max {
		t.Fatalf("ring size changed after put: n=%d want %d", p.n, p.max)
	}
	if p.head != (oldHead+1)&p.mask {
		t.Fatalf("head did not advance past the expired slot: got %d want %d", p.head, (oldHead+1)&p.mask)
	}
	if p.demoted.Load() != before+1 {
		t.Fatalf("demoted = %d, want %d after expired-head reuse", p.demoted.Load(), before+1)
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
	if p.buf == nil || len(p.buf) != p.cap {
		t.Fatalf("ring not allocated on first put: len(buf)=%d, cap=%d", len(p.buf), p.cap)
	}

	for range 1000 {
		got := GetBuffer(class)
		got[0] = 'x'
		PutBuffer(got)
	}
	if len(p.buf) != p.cap {
		t.Fatalf("ring backing array changed size after churn: len(buf)=%d, cap=%d", len(p.buf), p.cap)
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
	if s.Occupancy != 3 || s.Max != p.cap {
		t.Fatalf("Occupancy=%d Max=%d, want 3 / %d", s.Occupancy, s.Max, p.cap)
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

// TestRingGrowsOnOverflow verifies the ring grows from initialRingSize by
// doubling when filled, instead of committing a full-size array up front.
func TestRingGrowsOnOverflow(t *testing.T) {
	const class = 4096
	i := classIndex(class)
	resetClass(i)

	p := &classPools[i]
	if p.cap != initialRingSize {
		t.Fatalf("initial cap = %d, want %d", p.cap, initialRingSize)
	}
	for n := 0; n < initialRingSize+1; n++ {
		PutBuffer(make([]byte, class))
	}
	if p.cap != initialRingSize*2 {
		t.Fatalf("cap = %d, want %d after overflow", p.cap, initialRingSize*2)
	}
	if p.n != initialRingSize+1 {
		t.Fatalf("n = %d, want %d", p.n, initialRingSize+1)
	}
	resetClass(i)
}

// TestPoolStackTrace verifies that GetBuffer and PutBuffer caller stacks are
// recorded independently (gets and puts do not offset each other).
func TestPoolStackTrace(t *testing.T) {
	const class = 1024
	i := classIndex(class)
	resetClass(i)
	classPools[i].trace = traceTracker{}
	EnableTrackingStack.Store(true)
	defer EnableTrackingStack.Store(false)

	GetBuffer(class)               // one get
	PutBuffer(make([]byte, class)) // one put

	gets, puts := PoolStackTrace(class)
	if len(gets) != 1 || len(puts) != 1 {
		t.Fatalf("gets=%d puts=%d, want 1/1", len(gets), len(puts))
	}
	if !strings.Contains(gets[0].Stack, "buffer_test.go") {
		t.Fatalf("get stack should reference buffer_test.go, got: %s", gets[0].Stack)
	}
	if !strings.Contains(puts[0].Stack, "buffer_test.go") {
		t.Fatalf("put stack should reference buffer_test.go, got: %s", puts[0].Stack)
	}
}

// TestSweeperWarmSetKeepsLowRateClass verifies the production regression:
// a 16K-class pool whose whole occupancy sits inside the warm set survives
// the sweep even when every entry is idle past bucketTTL. Before the warm
// set existed, this scenario demoted everything and pinned the 16K HIT% at
// 71-77%.
func TestSweeperWarmSetKeepsLowRateClass(t *testing.T) {
	const class = 16384
	i := classIndex(class)
	resetClass(i)
	defer resetClass(i)

	p := &classPools[i]
	warmCount := max(classWarmMinBytes>>i, p.cap>>1) // 32: byte floor wins at cap 32
	for n := 0; n < warmCount; n++ {
		PutBuffer(make([]byte, class))
	}
	if p.n != warmCount {
		t.Fatalf("ring occupancy = %d, want %d", p.n, warmCount)
	}

	now := time.Now()
	p.mu.Lock()
	for j := 0; j < p.n; j++ {
		p.buf[(p.head+j)&p.mask].putTime = now.Add(-2 * bucketTTL) // all idle past TTL
	}
	p.mu.Unlock()

	p.sweepExpired(i, now)
	if p.n != warmCount {
		t.Fatalf("warm set demoted past fast TTL: n=%d, want %d", p.n, warmCount)
	}

	// Past the long tail the warm set does decay too: a fully idle class
	// releases even its warm residency.
	p.mu.Lock()
	for j := 0; j < p.n; j++ {
		p.buf[(p.head+j)&p.mask].putTime = now.Add(-2 * warmTTL)
	}
	p.mu.Unlock()

	p.sweepExpired(i, now)
	if p.n != 0 {
		t.Fatalf("warm set retained past warmTTL: n=%d, want 0", p.n)
	}
}

// TestSweeperDemotesAboveWarmSet verifies the other half of the contract:
// residency above the warm set still decays on the normal clock, so a
// traffic peak cannot pin memory forever.
func TestSweeperDemotesAboveWarmSet(t *testing.T) {
	const class = 16384
	i := classIndex(class)
	resetClass(i)
	defer resetClass(i)

	p := &classPools[i]
	floorCount := classWarmMinBytes >> i // 32 for the 16K class
	extra := 8
	for n := 0; n < floorCount+extra; n++ {
		PutBuffer(make([]byte, class))
	}

	// The 40 puts grew the ring to 64; warmCount = max(floor, cap/2) = 32.
	warmCount := max(classWarmMinBytes>>i, p.cap>>1)

	now := time.Now()
	p.mu.Lock()
	for j := 0; j < p.n; j++ {
		p.buf[(p.head+j)&p.mask].putTime = now.Add(-2 * bucketTTL)
	}
	p.mu.Unlock()

	// demoted is a per-class cumulative counter (resetClass does not clear
	// it), so assert on the delta like TestClassPoolPutReusesExpiredHead.
	before := p.demoted.Load()
	p.sweepExpired(i, now)
	if p.n != warmCount {
		t.Fatalf("above-warm excess not decayed: n=%d, want %d", p.n, warmCount)
	}
	if got := p.demoted.Load() - before; got != uint64(extra) {
		t.Fatalf("demoted delta = %d, want %d", got, extra)
	}
}

// TestSweeperWarmCountTracksRingGrowth pins the dynamic half of the warm
// set: a class whose ring grew (32 -> 64 -> 128 on the way to 100 buffers)
// keeps half the grown capacity warm, because the growth itself is evidence
// of a larger working set. A static warm floor would have let the excess
// decay again — the exact regression seen in production when the 16K
// working set grew past its warm cap.
func TestSweeperWarmCountTracksRingGrowth(t *testing.T) {
	const class = 16384
	i := classIndex(class)
	resetClass(i)
	defer resetClass(i)

	const count = 100 // grows the ring 32 -> 64 -> 128
	for n := 0; n < count; n++ {
		PutBuffer(make([]byte, class))
	}
	p := &classPools[i]
	if p.cap != 128 {
		t.Fatalf("ring cap = %d, want 128 after growth", p.cap)
	}

	now := time.Now()
	p.mu.Lock()
	for j := 0; j < p.n; j++ {
		p.buf[(p.head+j)&p.mask].putTime = now.Add(-2 * bucketTTL) // idle past fast TTL
	}
	p.mu.Unlock()

	// warmCount = max(512KiB/16KiB, 128/2) = 64: half the grown ring stays,
	// the excess decays.
	before := p.demoted.Load()
	p.sweepExpired(i, now)
	if p.n != 64 {
		t.Fatalf("n = %d, want 64 (cap/2 warm set)", p.n)
	}
	if got := p.demoted.Load() - before; got != count-64 {
		t.Fatalf("demoted delta = %d, want %d", got, count-64)
	}
}
