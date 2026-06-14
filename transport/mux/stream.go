package mux

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type stream struct {
	session *session
	id      uint16

	readMu   sync.Mutex
	readBuf  []byte
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

func (st *stream) pushData(data []byte) {
	st.readMu.Lock()
	st.readBuf = append(st.readBuf, data...)
	st.readCond.Signal()
	st.readMu.Unlock()
}

func (st *stream) closeRemote() {
	st.readMu.Lock()
	st.readEOF = true
	st.readCond.Broadcast()
	st.readMu.Unlock()
}

func (st *stream) terminate() {
	st.stopReadTimer()
	st.readMu.Lock()
	if st.readErr == nil {
		st.readErr = net.ErrClosed
	}
	st.readEOF = true
	st.readCond.Broadcast()
	st.readMu.Unlock()
}

func (st *stream) stopReadTimer() {
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

	for len(st.readBuf) == 0 && !st.readEOF && st.readErr == nil {
		if dl := st.readDeadline.Load(); dl != 0 && time.Now().UnixNano() > dl {
			return 0, &errTimeout{}
		}

		st.readCond.Wait()
	}

	if st.readErr != nil {
		return 0, st.readErr
	}
	if st.readEOF && len(st.readBuf) == 0 {
		return 0, io.EOF
	}

	n = copy(b, st.readBuf)
	st.readBuf = st.readBuf[n:]
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
		st.stopReadTimer()
		st.session.removeStream(st.id)
		if st.finSent.CompareAndSwap(false, true) {
			_ = st.session.writeEnd(st.id)
		}
		st.closeRemote()
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

	deadlineNano := deadlineNano(t)
	st.readDeadline.Store(deadlineNano)

	if st.readTimer != nil {
		st.readTimer.Stop()
		st.readTimer = nil
	}

	if !t.IsZero() {
		dur := time.Until(t)
		if dur <= 0 {
			st.readCond.Broadcast()
		} else {
			st.readTimer = time.AfterFunc(dur, func() {
				st.readCond.Broadcast()
				st.readDeadline.CompareAndSwap(deadlineNano, 0)
			})
		}
	}

	return nil
}

func (st *stream) SetWriteDeadline(t time.Time) error {
	st.writeDeadline.Store(deadlineNano(t))
	return nil
}
