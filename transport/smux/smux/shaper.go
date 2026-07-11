// MIT License
//
// Copyright (c) 2016-2017 xtaci
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

package smux

import (
	"container/list"
	"sync"
	"sync/atomic"
)

// streamQueue is a FIFO queue for writeRequests belonging to a single stream.
// It maintains two sub-queues: one for CLSCTRL (priority) and one for CLSDATA.
// Within each class, requests naturally arrive in FIFO order (seq is
// monotonically increasing), so a full heap is unnecessary — two slices suffice.
type streamQueue struct {
	ctrl    []writeRequest
	ctrlOff int
	data    []writeRequest
	dataOff int
}

func (q *streamQueue) push(req writeRequest) {
	if req.class == CLSCTRL {
		q.ctrl = append(q.ctrl, req)
	} else {
		q.data = append(q.data, req)
	}
}

func (q *streamQueue) pop() (writeRequest, bool) {
	if q.ctrlOff < len(q.ctrl) {
		req := q.ctrl[q.ctrlOff]
		q.ctrl[q.ctrlOff] = writeRequest{}
		q.ctrlOff++
		return req, true
	}
	if q.dataOff < len(q.data) {
		req := q.data[q.dataOff]
		q.data[q.dataOff] = writeRequest{}
		q.dataOff++
		return req, true
	}
	return writeRequest{}, false
}

func (q *streamQueue) empty() bool {
	return q.ctrlOff >= len(q.ctrl) && q.dataOff >= len(q.data)
}

// reset reuses the backing arrays of the queue after it has been fully drained.
func (q *streamQueue) reset() {
	q.ctrl = q.ctrl[:0]
	q.ctrlOff = 0
	q.data = q.data[:0]
	q.dataOff = 0
}

// streamQueuePool reduces allocations of streamQueue objects.
var streamQueuePool = sync.Pool{
	New: func() any {
		return &streamQueue{
			ctrl: make([]writeRequest, 0, 2),
			data: make([]writeRequest, 0, 16),
		}
	},
}

// shaperQueue manages multiple streams of writeRequests using a round-robin scheduling algorithm.
type shaperQueue struct {
	count   int64 // atomic counter for fast Len() and IsEmpty()
	streams map[uint32]*streamQueue
	rrList  *list.List    // list of sid (RR queue)
	next    *list.Element // next node to pop
	mu      sync.Mutex
}

func NewShaperQueue() *shaperQueue {
	return &shaperQueue{
		streams: make(map[uint32]*streamQueue),
		rrList:  list.New(),
	}
}

// Push adds a writeRequest to the shaperQueue.
func (sq *shaperQueue) Push(req writeRequest) {
	sq.mu.Lock()
	defer sq.mu.Unlock()

	sid := req.frame.sid
	if _, ok := sq.streams[sid]; !ok {
		q := streamQueuePool.Get().(*streamQueue)
		q.reset()
		sq.streams[sid] = q
		elem := sq.rrList.PushBack(sid)
		if sq.next == nil {
			sq.next = elem
		}
	}

	sq.streams[sid].push(req)
	atomic.AddInt64(&sq.count, 1)
}

// Pop uses Round Robin to pop writeRequests from the shaperQueue.
func (sq *shaperQueue) Pop() (req writeRequest, ok bool) {
	sq.mu.Lock()
	defer sq.mu.Unlock()

	if sq.next == nil || atomic.LoadInt64(&sq.count) == 0 {
		return writeRequest{}, false
	}

	start := sq.next
	current := start

	for {
		sid := current.Value.(uint32)
		q := sq.streams[sid]

		if !q.empty() {
			req, _ := q.pop()
			atomic.AddInt64(&sq.count, -1)

			// advance round-robin cursor
			next := current.Next()
			if next == nil {
				next = sq.rrList.Front()
			}
			sq.next = next

			if q.empty() {
				delete(sq.streams, sid)
				sq.rrList.Remove(current)
				q.reset()
				streamQueuePool.Put(q)
				if sq.rrList.Len() == 0 {
					sq.next = nil
				}
			}
			return req, true
		}

		current = current.Next()
		if current == nil {
			current = sq.rrList.Front()
		}
		if current == start {
			break
		}
	}

	return writeRequest{}, false
}

// IsEmpty checks if the shaperQueue is empty.
func (sq *shaperQueue) IsEmpty() bool {
	return atomic.LoadInt64(&sq.count) == 0
}

// Len returns the total number of writeRequests in the shaperQueue.
func (sq *shaperQueue) Len() int {
	return int(atomic.LoadInt64(&sq.count))
}
