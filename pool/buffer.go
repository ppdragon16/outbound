// https://github.com/nadoo/glider/blob/main/pkg/pool/buffer.go

package pool

import (
	"math/bits"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	// num is the number of size classes; maxsize is the largest buffer size.
	num     = 17
	maxsize = 1 << (num - 1)

	// bucketByteBudget caps how many bytes each size class may retain. The
	// per-class buffer count is derived from it, so a 4 KiB class holds up to
	// 2048 buffers and a 32 KiB class holds up to 256 (8 MiB each).
	bucketByteBudget = 2 << 22 // 8 MiB per size class

	// maxBucketCount additionally caps the number of buffers per size class,
	// so the tiniest classes don't retain an absurd number of entries.
	maxBucketCount = 4096

	// smallClassSize is the largest size class served directly by sync.Pool
	// instead of the GC-surviving ring. A ring entry is 32 bytes, so for
	// buffers this small the ring's fixed overhead dwarfs the payload; a plain
	// GC-cleared sync.Pool is enough and avoids committing a ring for them.
	smallClassSize = 16

	// initialRingSize is the starting capacity of a class ring. It grows by
	// doubling on overflow (see grow) up to the byte-budget cap, so a lightly
	// used class never commits a full-size ring entry array.
	initialRingSize = 32

	// bucketTTL is how long an idle buffer may sit in a pool before a
	// background sweeper releases it, so an idle process does not hold onto
	// peak memory forever.
	bucketTTL = 3 * time.Minute

	// sweepBatch caps how many expired entries the sweeper demotes from one
	// class per pass, so it never holds a bucket's lock long enough to stall
	// get/put. Leftover expired entries are drained on later passes.
	sweepBatch = 512
)

// bufEntry is a pooled buffer plus the time it was returned to the pool.
type bufEntry struct {
	ptr     *byte
	putTime time.Time
}

// classPool is a bounded, GC-surviving, TTL-aware FIFO ring for one size class.
//
// Unlike sync.Pool it is not cleared by the GC, so it survives the GC pressure
// that otherwise causes an allocation spiral. The ring is a fixed buf[max]
// indexed by head/n, so slots are reused forever with no reallocation and no
// head-drift — a slice queue would abandon its front slots on every pop and
// reallocate the backing array once the drift exhausted its capacity. The ring
// is allocated lazily on first put (only for classes that are actually used),
// and the sweeper evicts expired entries from the head in O(1).
type classPool struct {
	mu   sync.Mutex
	buf  []bufEntry // fixed size == cap, grown on demand (see grow)
	head int        // index of the oldest entry
	n    int        // number of live entries
	cap  int        // current ring capacity (power of two, grows toward max)
	mask int        // cap - 1
	max  int        // hard cap (bucketMax), immutable after init

	// Cumulative counters surfaced via PoolStats (see Stats). Updated with
	// atomics so they never contend with the ring mutex. Reuse efficiency is
	// the ratio of hits (ringHit+poolHit) to gets.
	gets    atomic.Uint64 // GetBuffer calls for this class (poolable sizes)
	puts    atomic.Uint64 // PutBuffer calls that pooled a buffer in this class
	ringHit atomic.Uint64 // served directly by the ring
	poolHit atomic.Uint64 // served by the sync.Pool fallback
	alloc   atomic.Uint64 // both tiers missed: served by a fresh make
	demoted atomic.Uint64 // ring entries evicted to sync.Pool by the sweeper

	// trace records caller stacks of outstanding GetBuffer calls (see
	// EnableTrackingStack). It is inert unless tracking is enabled.
	trace traceTracker
}

var (
	pools      [num]sync.Pool // sync.Pool fallback: overflow, cleared by the GC
	classPools [num]classPool // bounded, GC-surviving primary

	// EnableTrackingStack records the caller stack of every GetBuffer and
	// offsets it on PutBuffer, so PoolStackTrace can report leaked buffers.
	// It is off by default and should only be enabled for leak diagnosis.
	EnableTrackingStack atomic.Bool
)

func init() {
	for i := range num {
		size := 1 << i
		classPools[i].max = bucketMax(size)
		classPools[i].cap = min(initialRingSize, classPools[i].max)
		classPools[i].mask = classPools[i].cap - 1
		// sync.Pool is a best-effort recycle bin only: with no New, Get returns
		// nil on a miss so GetBuffer can count a real allocation (see Alloc).
	}
	// Starts a background goroutine that periodically demotes expired buffers
	// from every class ring into the sync.Pool fallback. The ring itself drops
	// nothing here: the buffer stays reusable until the GC next clears sync.Pool,
	// at which point an idle process's peak memory is actually released.
	go func() {
		t := time.NewTicker(bucketTTL / 2)
		defer t.Stop()
		for range t.C {
			expiredTime := time.Now().Add(-bucketTTL)
			for i := range classPools {
				p := &classPools[i]
				p.mu.Lock()
				for j := 0; j < sweepBatch && p.n > 0 && p.buf[p.head].putTime.Before(expiredTime); j++ {
					pools[i].Put(p.buf[p.head].ptr) // demote to the GC-cleared fallback
					p.demoted.Add(1)
					p.buf[p.head] = bufEntry{}
					p.head = (p.head + 1) & p.mask
					p.n--
				}
				p.mu.Unlock()
			}
		}
	}()
}

// bucketMax returns the max number of buffers a size class may retain: the
// byte budget divided by the class size, clamped to maxBucketCount. Every
// result is a power of two.
func bucketMax(size int) int {
	if m := bucketByteBudget / size; m < maxBucketCount {
		return m
	}
	return maxBucketCount
}

// GetBuffer gets a buffer from pool, size should in range: [1, 65536],
// otherwise, this function will call make([]byte, size) directly.
func GetBuffer(size int) []byte {
	if size >= 1 && size <= maxsize {
		i := bits.Len32(uint32(size - 1))
		class := 1 << i
		classPools[i].gets.Add(1)
		if EnableTrackingStack.Load() {
			classPools[i].trace.get(captureStack())
		}
		if class > smallClassSize {
			if b := classPools[i].get(class, size); b != nil {
				classPools[i].ringHit.Add(1)
				return b
			}
		}
		if p := pools[i].Get(); p != nil {
			classPools[i].poolHit.Add(1)
			return unsafe.Slice(p.(*byte), class)[:size]
		}
		classPools[i].alloc.Add(1)
		return make([]byte, class)[:size] // class-sized, so PutBuffer pools it back
	}
	return make([]byte, size)
}

// PutBuffer puts a buffer into pool.
func PutBuffer(buf []byte) {
	// Only power-of-2 capacities may enter a bucket: GetBuffer re-slices pooled
	// buffers to the requested size, so a non-power-of-2 cap (grown by append)
	// stored in the next bucket would panic on a later GetBuffer.
	if size := cap(buf); size >= 1 && size <= maxsize && size&(size-1) == 0 {
		i := bits.Len32(uint32(size - 1))
		class := 1 << i
		classPools[i].puts.Add(1)
		if EnableTrackingStack.Load() {
			classPools[i].trace.put(captureStack())
		}
		ptr := unsafe.SliceData(buf)
		if class <= smallClassSize {
			// Tiny class: no ring, straight to the GC-cleared pool.
			pools[i].Put(ptr)
			return
		}
		if !classPools[i].put(ptr) {
			// Ring full: fall back to sync.Pool. It is cleared by the GC,
			// so overflow buffers are only kept best-effort.
			pools[i].Put(ptr)
		}
	}
}

// get pops the oldest buffer, or nil if the pool is empty. It deliberately does
// not check the entry's TTL: an expired buffer is still valid memory and get is
// the reuse path — reusing it is what avoids an allocation. Idle memory is
// released by the sweeper instead.
func (p *classPool) get(class, req int) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n == 0 {
		return nil
	}
	e := p.buf[p.head]
	p.buf[p.head] = bufEntry{}
	p.head = (p.head + 1) & p.mask
	p.n--
	return unsafe.Slice(e.ptr, class)[:req]
}

// put appends ptr to the ring unless it is full. It reports whether the buffer
// was accepted (false means the caller should fall back to sync.Pool). When the
// ring is full it reuses the head slot only if that entry has already expired —
// entries are inserted in time order so the head is the oldest, and if it is not
// expired then nothing is. Bulk expiry is the sweeper's job; put evicts at most
// one entry to keep the hot path O(1).
func (p *classPool) put(ptr *byte) bool {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.buf == nil {
		p.buf = make([]bufEntry, p.cap)
	}
	if p.n == p.cap {
		if now.Sub(p.buf[p.head].putTime) > bucketTTL {
			// Reuse the expired head slot (no growth needed).
			p.buf[p.head] = bufEntry{ptr: ptr, putTime: now}
			p.head = (p.head + 1) & p.mask
			return true
		}
		// Ring full and head fresh: grow if below the hard cap, else overflow.
		if p.cap < p.max {
			p.grow()
		} else {
			return false
		}
	}
	p.buf[(p.head+p.n)&p.mask] = bufEntry{ptr: ptr, putTime: now}
	p.n++
	return true
}

// grow doubles the ring capacity (up to max), re-lining the live entries so
// head becomes 0. Callers hold p.mu.
func (p *classPool) grow() {
	newCap := min(p.cap*2, p.max)
	buf := make([]bufEntry, newCap)
	for i := 0; i < p.n; i++ {
		buf[i] = p.buf[(p.head+i)&p.mask]
	}
	p.buf = buf
	p.head = 0
	p.mask = newCap - 1
	p.cap = newCap
}

// Stats is a per-class snapshot filled by PoolStats into a StatsSnapshot. The
// counters are
// cumulative since process start; Occupancy and Max describe the ring's current
// fill. Reuse efficiency is a rate, so it is derived from the counters (see
// HitRate and RingHitRate) rather than stored.
type Stats struct {
	Gets      uint64 // GetBuffer calls for this class (poolable sizes)
	Puts      uint64 // PutBuffer calls that pooled a buffer in this class
	RingHit   uint64 // served directly by the ring
	PoolHit   uint64 // served by the sync.Pool fallback
	Alloc     uint64 // both tiers missed: served by a fresh make
	Demoted   uint64 // ring entries evicted to sync.Pool by the sweeper
	Occupancy int    // live buffers currently held by the ring
	Max       int    // current ring capacity (grows from initialRingSize)
}

// HitRate is the overall reuse efficiency: the fraction of GetBuffer calls
// served by a pooled buffer instead of a fresh allocation.
func (s Stats) HitRate() float64 {
	if s.Gets == 0 {
		return 0
	}
	return float64(s.Gets-s.Alloc) / float64(s.Gets)
}

// RingHitRate is the fraction of GetBuffer calls served by the GC-surviving
// ring specifically — the tier that keeps reuse alive under GC pressure.
func (s Stats) RingHitRate() float64 {
	if s.Gets == 0 {
		return 0
	}
	return float64(s.RingHit) / float64(s.Gets)
}

// StatsSnapshot is a fixed-size array of per-class Stats, indexed by class
// index (1 << i). PoolStats fills it in place so callers can reuse a single
// snapshot across samples without reallocating.
type StatsSnapshot [num]Stats

// PoolStats fills dst with a snapshot of every class pool's counters and
// occupancy. The caller owns dst and may reuse it across samples to avoid
// allocating on every read.
func PoolStats(dst *StatsSnapshot) {
	for i := range classPools {
		dst[i] = classPools[i].stats()
	}
}

// stats snapshots one class pool. Occupancy is read under the ring mutex so it
// is consistent; max is immutable after init; the counters are atomic loads.
func (p *classPool) stats() Stats {
	p.mu.Lock()
	n := p.n
	c := p.cap
	p.mu.Unlock()
	return Stats{
		Gets:      p.gets.Load(),
		Puts:      p.puts.Load(),
		RingHit:   p.ringHit.Load(),
		PoolHit:   p.poolHit.Load(),
		Alloc:     p.alloc.Load(),
		Demoted:   p.demoted.Load(),
		Occupancy: n,
		Max:       c,
	}
}

// StackTraceEntry is one caller stack recorded for a GetBuffer or PutBuffer,
// with its count.
type StackTraceEntry struct {
	Stack string
	Count int
}

// traceTracker records the caller stacks of GetBuffer and PutBuffer calls for
// one size class, each counted independently. A leaked buffer shows up as a get
// stack with a higher count than the matching put stack.
type traceTracker struct {
	mu        sync.Mutex
	getTraces map[string]int
	putTraces map[string]int
}

func (t *traceTracker) get(stack string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.getTraces == nil {
		t.getTraces = make(map[string]int)
	}
	t.getTraces[stack]++
}

func (t *traceTracker) put(stack string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.putTraces == nil {
		t.putTraces = make(map[string]int)
	}
	t.putTraces[stack]++
}

func (t *traceTracker) snapshot() (gets, puts []StackTraceEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	gets = make([]StackTraceEntry, 0, len(t.getTraces))
	for stack, count := range t.getTraces {
		gets = append(gets, StackTraceEntry{Stack: stack, Count: count})
	}
	sort.Slice(gets, func(i, j int) bool { return gets[i].Count > gets[j].Count })
	puts = make([]StackTraceEntry, 0, len(t.putTraces))
	for stack, count := range t.putTraces {
		puts = append(puts, StackTraceEntry{Stack: stack, Count: count})
	}
	sort.Slice(puts, func(i, j int) bool { return puts[i].Count > puts[j].Count })
	return gets, puts
}

// captureStack returns the caller stack with one frame per line, skipping
// runtime frames and the pool's own frames so it starts at the caller.
func captureStack() string {
	var pcs [16]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	var sb strings.Builder
	depth := 0
	for {
		frame, more := frames.Next()
		if strings.HasPrefix(frame.Function, "runtime.") {
			if !more {
				break
			}
			continue
		}
		if depth > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(shortFile(frame.File))
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(frame.Line))
		depth++
		if depth >= 5 || !more {
			break
		}
	}
	return sb.String()
}

// shortFile renders a frame's file path as its last two components
// (dir/file.go) so a module-cache path like
// "github.com/.../outbound@v0.0.0-.../protocol/anytls/session.go" becomes
// "anytls/session.go".
func shortFile(f string) string {
	base := filepath.Base(f)
	dir := filepath.Base(filepath.Dir(f))
	if dir == "." || dir == "/" || dir == "" {
		return base
	}
	return dir + "/" + base
}

// PoolStackTrace reports the GetBuffer and PutBuffer caller stacks for one
// size class, as two lists each sorted by count descending. class is the class
// size (1, 2, 4, ... 65536), e.g. 1024 for the 1K bucket. Both are empty unless
// EnableTrackingStack was set while the buffers were acquired.
func PoolStackTrace(class int) (gets, puts []StackTraceEntry) {
	if class < 1 || class > maxsize {
		return nil, nil
	}
	i := bits.Len32(uint32(class - 1))
	return classPools[i].trace.snapshot()
}
