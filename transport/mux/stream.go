package mux

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

// maxStreamBuffer is the maximum number of bytes a stream's queue can hold
// before readData blocks, providing TCP backpressure.
const maxStreamBuffer = 256 * 1024

// bufNode is a node in the stream's data queue.
// Each node holds a slice referencing a pooled buffer.
type bufNode struct {
	buf  []byte // pool.GetBuffer(4096), len = valid bytes in this chunk
	off  int    // bytes already consumed by Read
	next *bufNode
}

type stream struct {
	session *session
	id      uint16

	readMu   sync.Mutex
	head     *bufNode // first node (Read consumes from here)
	tail     *bufNode // last node (readData appends here)
	queued   int      // total unread bytes across all nodes
	readEOF  bool
	readErr  error
	readCond *sync.Cond

	closed  atomic.Bool
	finSent atomic.Bool

	// Per-stream deadlines. readDeadline and writeDeadline use atomic
	// to avoid mutex contention on the hot Read/Write paths.
	// readTimerMu protects readTimer (the AfterFunc that broadcasts
	// readCond when the read deadline expires).
	readDeadline  atomic.Int64 // unix nano, 0 = none
	readTimer     *time.Timer
	readTimerMu   sync.Mutex
	writeDeadline atomic.Int64 // unix nano, 0 = none
}

// deadlineNano converts a time.Time to unix nano (0 means no deadline).
func deadlineNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// errTimeout implements net.Error with Timeout()=true.
type errTimeout struct{}

func (e *errTimeout) Error() string   { return "i/o timeout" }
func (e *errTimeout) Timeout() bool   { return true }
func (e *errTimeout) Temporary() bool { return false }

func newStream(s *session, id uint16) *stream {
	st := &stream{
		session: s,
		id:      id,
	}
	st.readCond = sync.NewCond(&st.readMu)
	return st
}

// readData reads a single data frame from reader: first the 2-byte
// length, then the payload in 4KB chunks into the queue. Each chunk
// is a pool buffer appended to the internal linked list.
// Blocks if queued >= maxStreamBuffer until Read() drains data
// or the stream is closed.
//
// On fatal I/O error the error is returned to the caller (session.run).
// On stream-close the remaining bytes are drained from reader and nil
// is returned (data discarded, session stays alive).
func (st *stream) readData(reader io.Reader) error {
	var dataLen [2]byte
	if _, err := io.ReadFull(reader, dataLen[:]); err != nil {
		return err
	}
	remain := int(binary.BigEndian.Uint16(dataLen[:]))
	for remain > 0 {
		st.readMu.Lock()
		for st.queued >= maxStreamBuffer && st.readErr == nil {
			st.readCond.Wait()
		}
		if st.readErr != nil {
			st.readMu.Unlock()
			_, _ = io.CopyN(io.Discard, reader, int64(remain))
			return nil
		}
		st.readMu.Unlock()

		chunk := min(remain, 4096)
		buf := pool.GetBuffer(chunk)
		if _, err := io.ReadFull(reader, buf); err != nil {
			pool.PutBuffer(buf)
			return err
		}

		node := &bufNode{buf: buf}

		st.readMu.Lock()
		if st.tail == nil {
			st.head = node
		} else {
			st.tail.next = node
		}
		st.tail = node
		st.queued += chunk
		remain -= chunk
		st.readCond.Signal()
		st.readMu.Unlock()
	}
	return nil
}

// drainQueue returns all queued pool buffers and resets the queue.
// Must be called with readMu held.
func (st *stream) drainQueue() {
	for st.head != nil {
		next := st.head.next
		pool.PutBuffer(st.head.buf)
		st.head = next
	}
	st.tail = nil
	st.queued = 0
}

func (st *stream) closeRemote() {
	st.readMu.Lock()
	st.readEOF = true
	st.readCond.Broadcast()
	st.readMu.Unlock()
}

func (st *stream) terminate() {
	st.clearReadTimer()
	st.readMu.Lock()
	if st.readErr == nil {
		st.readErr = net.ErrClosed
	}
	st.readEOF = true
	st.drainQueue()
	st.readCond.Broadcast()
	st.readMu.Unlock()
}

func (st *stream) clearReadTimer() {
	st.readTimerMu.Lock()
	defer st.readTimerMu.Unlock()
	if st.readTimer != nil {
		st.readTimer.Stop()
		st.readTimer = nil
	}
}

func (st *stream) Read(b []byte) (n int, err error) {
	if st.closed.Load() {
		return 0, net.ErrClosed
	}

	st.readMu.Lock()
	defer st.readMu.Unlock()

	for st.head == nil && !st.readEOF && st.readErr == nil {
		if dl := st.readDeadline.Load(); dl != 0 && time.Now().UnixNano() > dl {
			return 0, &errTimeout{}
		}

		st.readCond.Wait()
	}

	if st.readErr != nil {
		st.drainQueue()
		return 0, st.readErr
	}
	if st.readEOF && st.head == nil {
		return 0, io.EOF
	}

	for st.head != nil && n < len(b) {
		node := st.head
		m := copy(b[n:], node.buf[node.off:])
		n += m
		node.off += m
		st.queued -= m

		if node.off == len(node.buf) {
			pool.PutBuffer(node.buf)
			st.head = node.next
			if st.head == nil {
				st.tail = nil
			}
		}
	}

	// Wake up readData — it may be blocked waiting for queue space.
	st.readCond.Signal()

	return n, nil
}

func (st *stream) Write(b []byte) (n int, err error) {
	if st.closed.Load() {
		return 0, net.ErrClosed
	}

	if dl := st.writeDeadline.Load(); dl != 0 && time.Now().UnixNano() > dl {
		return 0, &errTimeout{}
	}

	n, err = st.session.writeData(st.id, b)

	// Check again after write: deadline may have expired while
	// writeData was blocked on the shared TCP connection.
	if dl := st.writeDeadline.Load(); dl != 0 && time.Now().UnixNano() > dl {
		return n, &errTimeout{}
	}
	return n, err
}

func (st *stream) Close() error {
	if st.closed.CompareAndSwap(false, true) {
		st.clearReadTimer()
		st.session.removeStream(st.id)
		if st.finSent.CompareAndSwap(false, true) {
			_ = st.session.writeEnd(st.id)
		}
		st.closeRemote()

		// Drain queue and set readErr to wake up readData if it is
		// blocked waiting for buffer space. closeRemote only sets
		// readEOF, which readData does not check.
		st.readMu.Lock()
		if st.readErr == nil {
			st.readErr = net.ErrClosed
		}
		st.drainQueue()
		st.readCond.Broadcast()
		st.readMu.Unlock()
	}
	return nil
}

func (st *stream) CloseWrite() error {
	if st.finSent.CompareAndSwap(false, true) {
		_ = st.session.writeEnd(st.id)
	}
	return nil
}

func (st *stream) LocalAddr() net.Addr {
	return st.session.conn.LocalAddr()
}

func (st *stream) RemoteAddr() net.Addr {
	return st.session.conn.RemoteAddr()
}

func (st *stream) SetDeadline(t time.Time) error {
	st.SetReadDeadline(t)
	st.SetWriteDeadline(t)
	return nil
}

func (st *stream) SetReadDeadline(t time.Time) error {
	st.readTimerMu.Lock()
	defer st.readTimerMu.Unlock()

	st.readDeadline.Store(deadlineNano(t))

	if st.readTimer != nil {
		st.readTimer.Stop()
	}

	if t.IsZero() {
		st.readTimer = nil
		return nil
	}

	dur := time.Until(t)
	if dur <= 0 {
		st.readTimer = nil
		st.readCond.Broadcast()
		return nil
	}

	if st.readTimer == nil {
		st.readTimer = time.AfterFunc(dur, st.readTimerCallback)
	} else {
		st.readTimer.Reset(dur)
	}

	return nil
}

func (st *stream) readTimerCallback() {
	dl := st.readDeadline.Load()
	if dl == 0 || time.Now().UnixNano() < dl {
		return
	}
	st.readCond.Broadcast()
}

func (st *stream) SetWriteDeadline(t time.Time) error {
	st.writeDeadline.Store(deadlineNano(t))
	return nil
}
