// https://github.com/nadoo/glider/blob/main/pkg/pool/buffer.go

package pool

import (
	"math/bits"
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
	// 512 buffers and a 32 KiB class holds up to 64 (2 MiB each).
	bucketByteBudget = 2 << 20 // 2 MiB per size class

	// maxBucketCount additionally caps the number of buffers per size class,
	// so the tiniest classes don't retain an absurd number of entries (the
	// byte budget alone would allow ~2M one-byte buffers).
	maxBucketCount = 2048

	// smallClassSize is the largest size class served directly by sync.Pool
	// instead of the GC-surviving ring. A ring entry is 32 bytes, so for
	// buffers this small the ring's fixed overhead dwarfs the payload; a plain
	// GC-cleared sync.Pool is enough and avoids committing a ring for them.
	smallClassSize = 16

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
	buf  []bufEntry // fixed size == max, allocated lazily on first put
	head int        // index of the oldest entry
	n    int        // number of live entries
	max  int        // max live buffers (see bucketMax)
	mask int        // max - 1; max is a power of two, so & mask == % max

	// Cumulative counters surfaced via PoolStats (see Stats). Updated with
	// atomics so they never contend with the ring mutex. Reuse efficiency is
	// the ratio of hits (ringHit+poolHit) to gets.
	gets    atomic.Uint64 // GetBuffer calls for this class (poolable sizes)
	ringHit atomic.Uint64 // served directly by the ring
	poolHit atomic.Uint64 // served by the sync.Pool fallback
	alloc   atomic.Uint64 // both tiers missed: served by a fresh make
	demoted atomic.Uint64 // ring entries evicted to sync.Pool by the sweeper
}

var (
	pools      [num]sync.Pool // sync.Pool fallback: overflow, cleared by the GC
	classPools [num]classPool // bounded, GC-surviving primary
)

func init() {
	for i := range num {
		size := 1 << i
		classPools[i].max = bucketMax(size)
		classPools[i].mask = classPools[i].max - 1
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
		p.buf = make([]bufEntry, p.max)
	}
	if p.n == p.max {
		if now.Sub(p.buf[p.head].putTime) <= bucketTTL {
			return false
		}
		// Reuse the expired head slot.
		p.buf[p.head] = bufEntry{ptr: ptr, putTime: now}
		p.head = (p.head + 1) & p.mask
	} else {
		p.buf[(p.head+p.n)&p.mask] = bufEntry{ptr: ptr, putTime: now}
		p.n++
	}
	return true
}

// Stats is a per-class snapshot filled by PoolStats into a StatsSnapshot. The
// counters are
// cumulative since process start; Occupancy and Max describe the ring's current
// fill. Reuse efficiency is a rate, so it is derived from the counters (see
// HitRate and RingHitRate) rather than stored.
type Stats struct {
	Gets      uint64 // GetBuffer calls for this class (poolable sizes)
	RingHit   uint64 // served directly by the ring
	PoolHit   uint64 // served by the sync.Pool fallback
	Alloc     uint64 // both tiers missed: served by a fresh make
	Demoted   uint64 // ring entries evicted to sync.Pool by the sweeper
	Occupancy int    // live buffers currently held by the ring
	Max       int    // ring capacity (bucketMax)
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
	p.mu.Unlock()
	return Stats{
		Gets:      p.gets.Load(),
		RingHit:   p.ringHit.Load(),
		PoolHit:   p.poolHit.Load(),
		Alloc:     p.alloc.Load(),
		Demoted:   p.demoted.Load(),
		Occupancy: n,
		Max:       p.max,
	}
}
