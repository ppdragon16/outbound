// MIT License
//
// Copyright (c) 2016-2017 xtaci
// Copyright (c) 2025 daeuniverse
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// [daeuniverse fork] Replaced sync.Pool with channel-based pool.
// The original sync.Pool-based Allocator was cleared on every GC cycle,
// causing repeated large allocations (up to 64KB) under high throughput.
// A channel-based buffer pool is immune to GC and provides stable buffer reuse.

package smux

import (
	"errors"

	"github.com/daeuniverse/outbound/pool"
)

var (
	defaultAllocator *Allocator
	debruijnPos      = [...]byte{0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30, 8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31}
)

// poolCap limits the number of buffers cached per size tier.
// When full, Put drops the buffer (non-blocking) and lets GC reclaim it.
const poolCap = 64

func init() {
	defaultAllocator = NewAllocator()
}

// Allocator for incoming frames, optimized to prevent overwriting after zeroing.
// Uses channel-based pools that are NOT cleared by GC, unlike sync.Pool.
type Allocator struct {
	buffers []chan *[]byte
}

// NewAllocator initiates a []byte allocator for frames less than 65536 bytes,
// the waste(memory fragmentation) of space allocation is guaranteed to be
// no more than 50%.
func NewAllocator() *Allocator {
	alloc := &Allocator{
		buffers: make([]chan *[]byte, 17), // 1B -> 64K
	}
	for k := range alloc.buffers {
		alloc.buffers[k] = make(chan *[]byte, poolCap)
	}
	return alloc
}

// Get a []byte from pool with most appropriate cap.
func (alloc *Allocator) Get(size int) *[]byte {
	if size <= 0 || size > 65536 {
		return nil
	}

	bits := msb(size)
	if size == 1<<bits {
		return alloc.get(bits, size)
	}
	return alloc.get(bits+1, size)
}

func (alloc *Allocator) get(bits byte, size int) *[]byte {
	select {
	case p := <-alloc.buffers[bits]:
		*p = (*p)[:size]
		return p
	default:
		b := make([]byte, 1<<bits)
		p := &b
		*p = b[:size]
		return p
	}
}

// Put returns a []byte to pool for future use,
// which the cap must be exactly 2^n.
func (alloc *Allocator) Put(p *[]byte) error {
	if p == nil {
		return errors.New("allocator Put() incorrect buffer size")
	}
	bits := msb(cap(*p))
	if cap(*p) == 0 || cap(*p) > 65536 || cap(*p) != 1<<bits {
		return errors.New("allocator Put() incorrect buffer size")
	}
	select {
	case alloc.buffers[bits] <- p:
	default:
		// Channel pool full — overflow into dae's global buffer pool
		// so that relayDirection can reuse the memory.
		pool.PutBuffer(*p)
	}
	return nil
}

// msb returns the pos of most significant bit
// http://supertech.csail.mit.edu/papers/debruijn.pdf
func msb(size int) byte {
	v := uint32(size)
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	return debruijnPos[(v*0x07C4ACDD)>>27]
}
