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
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

const (
	defaultAcceptBacklog = 1024
	maxShaperSize        = 1024
	openCloseTimeout     = 30 * time.Second // Timeout for opening/closing streams

	// frameReadBufferSize is superseded by frameReader: the recvLoop read
	// buffer now starts at 2KiB and grows adaptively to 32KiB on evidence
	// of large arrival bursts (see frame_reader.go).

	// write-batch bounds: how much already-queued traffic sendLoop may merge
	// into a single underlying write. Frames are self-delimiting and TCP
	// preserves order, so merging is protocol-transparent; the bounds only
	// cap syscall amortization so a deep queue cannot balloon one buffer.
	// Requests still queued go out on the next loop round-trip, so merging
	// adds no latency of its own.
	maxWriteBatchFrames = 16
	maxWriteBatchBytes  = 32 << 10
)

// resultChanPool reduces allocation of result channels
var resultChanPool = sync.Pool{
	New: func() any {
		return make(chan writeResult, 1)
	},
}

// CLASSID represents the class of a frame
type CLASSID int

const (
	CLSCTRL CLASSID = iota // prioritized control signal
	CLSDATA
)

// timeoutError representing timeouts for operations such as accept, read and write
//
// To better cooperate with the standard library, timeoutError should implement the standard library's `net.Error`.
//
// For example, using smux to implement net.Listener and work with http.Server, the keep-alive connection (*smux.Stream) will be unexpectedly closed.
// For more details, see https://github.com/xtaci/smux/pull/99.
type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Temporary() bool { return true }
func (timeoutError) Timeout() bool   { return true }

var (
	ErrInvalidProtocol           = errors.New("invalid protocol")
	ErrConsumed                  = errors.New("peer consumed more than sent")
	ErrGoAway                    = errors.New("stream id overflows, should start a new connection")
	ErrTimeout         net.Error = &timeoutError{}
	ErrWouldBlock                = errors.New("operation would block on IO")
)

// writeRequest represents a request to write a frame
type writeRequest struct {
	class  CLASSID
	frame  Frame
	result chan writeResult
}

// writeResult represents the result of a write request
type writeResult struct {
	n   int
	err error
}

// Session defines a multiplexed connection for streams
type Session struct {
	conn io.ReadWriteCloser

	config           *Config
	goAway           int32  // flag id exhausted
	nextStreamID     uint32 // next stream identifier
	nextStreamIDLock sync.Mutex

	bucket       int32         // token bucket
	bucketNotify chan struct{} // used for waiting for tokens

	streams    map[uint32]*stream // all streams in this session
	streamLock sync.Mutex         // locks streams

	die     chan struct{} // flag session has died
	dieOnce sync.Once
	closed  int32 // atomic flag for fast IsClosed check

	// socket error handling
	socketReadError      atomic.Value
	socketWriteError     atomic.Value
	chSocketReadError    chan struct{}
	chSocketWriteError   chan struct{}
	socketReadErrorOnce  sync.Once
	socketWriteErrorOnce sync.Once

	// smux protocol errors
	protoError     atomic.Value
	chProtoError   chan struct{}
	protoErrorOnce sync.Once

	chAccepts chan *stream

	sessionIsActive int32        // flag session is active
	acceptDeadline  atomic.Value // deadline for Accept()

	// OnIdle is called when the last stream closes and the session has no
	// active streams. It is invoked while streamLock is held.
	OnIdle func()

	shaper           chan writeRequest // a shaper for writing
	sq               *shaperQueue
	chShaperPending  chan struct{}
	chShaperConsumed chan struct{}
}

func newSession(config *Config, conn io.ReadWriteCloser, client bool) *Session {
	nextStreamID := uint32(0)
	if client {
		nextStreamID = 1
	}

	s := &Session{
		conn:               conn,
		config:             config,
		nextStreamID:       nextStreamID,
		streams:            make(map[uint32]*stream),
		chAccepts:          make(chan *stream, defaultAcceptBacklog),
		bucket:             int32(config.MaxReceiveBuffer),
		bucketNotify:       make(chan struct{}, 1),
		shaper:             make(chan writeRequest, maxShaperSize),
		chSocketReadError:  make(chan struct{}),
		chSocketWriteError: make(chan struct{}),
		chProtoError:       make(chan struct{}),
		chShaperPending:    make(chan struct{}, 1),
		chShaperConsumed:   make(chan struct{}, 1),
		sq:                 NewShaperQueue(),
		die:                make(chan struct{}),
	}

	go s.shaperLoop()
	go s.recvLoop()
	go s.sendLoop()
	if !config.KeepAliveDisabled {
		go s.keepalive()
	}
	return s
}

// OpenStream is used to create a new stream
func (s *Session) OpenStream() (*Stream, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	// generate stream id
	s.nextStreamIDLock.Lock()
	if s.goAway > 0 {
		s.nextStreamIDLock.Unlock()
		return nil, ErrGoAway
	}

	// check for stream id overflow
	if s.nextStreamID+2 < s.nextStreamID {
		s.goAway = 1
		s.nextStreamIDLock.Unlock()
		return nil, ErrGoAway
	}

	// allocate next stream id
	s.nextStreamID += 2
	sid := s.nextStreamID
	s.nextStreamIDLock.Unlock()

	stream := newStream(sid, s.config.MaxFrameSize, s)

	if _, err := s.writeControlFrame(newFrame(byte(s.config.Version), cmdSYN, sid)); err != nil {
		return nil, err
	}

	s.streamLock.Lock()
	defer s.streamLock.Unlock()
	select {
	case <-s.chSocketReadError:
		return nil, s.socketReadError.Load().(error)
	case <-s.chSocketWriteError:
		return nil, s.socketWriteError.Load().(error)
	case <-s.die:
		return nil, io.ErrClosedPipe
	default:
		s.streams[sid] = stream
		wrapper := &Stream{stream: stream}
		// NOTE(x): disabled finalizer for issue #997
		/*
			runtime.SetFinalizer(wrapper, func(s *Stream) {
				s.Close()
			})
		*/
		return wrapper, nil
	}
}

// Open returns a generic ReadWriteCloser
func (s *Session) Open() (io.ReadWriteCloser, error) {
	return s.OpenStream()
}

// AcceptStream is used to block until the next available stream
// is ready to be accepted.
func (s *Session) AcceptStream() (*Stream, error) {
	var deadline <-chan time.Time
	if d, ok := s.acceptDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case stream := <-s.chAccepts:
		wrapper := &Stream{stream: stream}
		runtime.SetFinalizer(wrapper, func(s *Stream) {
			s.Close()
		})
		return wrapper, nil
	case <-deadline:
		return nil, ErrTimeout
	case <-s.chSocketReadError:
		return nil, s.socketReadError.Load().(error)
	case <-s.chProtoError:
		return nil, s.protoError.Load().(error)
	case <-s.die:
		return nil, io.ErrClosedPipe
	}
}

// Accept Returns a generic ReadWriteCloser instead of smux.Stream
func (s *Session) Accept() (io.ReadWriteCloser, error) {
	return s.AcceptStream()
}

// Close is used to close the session and all streams.
func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		atomic.StoreInt32(&s.closed, 1)
		close(s.die)
		once = true
	})

	if !once {
		return io.ErrClosedPipe
	}

	s.streamLock.Lock()
	for k := range s.streams {
		s.streams[k].sessionClose()
	}
	s.streamLock.Unlock()
	return s.conn.Close()
}

// CloseChan can be used by someone who wants to be notified immediately when this
// session is closed
func (s *Session) CloseChan() <-chan struct{} {
	return s.die
}

// notifyBucket notifies recvLoop that bucket is available
func (s *Session) notifyBucket() {
	select {
	case s.bucketNotify <- struct{}{}:
	default:
	}
}

func (s *Session) notifyReadError(err error) {
	s.socketReadErrorOnce.Do(func() {
		s.socketReadError.Store(err)
		close(s.chSocketReadError)
	})
	s.Close()
}

func (s *Session) notifyWriteError(err error) {
	s.socketWriteErrorOnce.Do(func() {
		s.socketWriteError.Store(err)
		close(s.chSocketWriteError)
	})
	s.Close()
}

func (s *Session) notifyProtoError(err error) {
	s.protoErrorOnce.Do(func() {
		s.protoError.Store(err)
		close(s.chProtoError)
	})
	s.Close()
}

// IsClosed does a safe check to see if we have shutdown
func (s *Session) IsClosed() bool {
	return atomic.LoadInt32(&s.closed) != 0
}

// IsStreamIDFull returns true if the session cannot create new streams due to
// stream ID exhaustion or overflow.
func (s *Session) IsStreamIDFull() bool {
	s.nextStreamIDLock.Lock()
	defer s.nextStreamIDLock.Unlock()
	if s.goAway > 0 {
		return true
	}
	if s.nextStreamID+2 < s.nextStreamID {
		return true
	}
	return false
}

// NumStreams returns the number of currently open streams
func (s *Session) NumStreams() int {
	if s.IsClosed() {
		return 0
	}
	s.streamLock.Lock()
	defer s.streamLock.Unlock()
	return len(s.streams)
}

// SetDeadline sets a deadline used by Accept* calls.
// A zero time value disables the deadline.
func (s *Session) SetDeadline(t time.Time) error {
	s.acceptDeadline.Store(t)
	return nil
}

// LocalAddr satisfies net.Conn interface
func (s *Session) LocalAddr() net.Addr {
	if ts, ok := s.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Session) RemoteAddr() net.Addr {
	if ts, ok := s.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

// notify the session that a stream has closed
func (s *Session) streamClosed(sid uint32) {
	s.streamLock.Lock()
	defer s.streamLock.Unlock()

	stream, ok := s.streams[sid]
	if !ok {
		return
	}

	if n := stream.recycleTokens(); n > 0 {
		// return remaining tokens to the bucket
		if atomic.AddInt32(&s.bucket, int32(n)) > 0 {
			s.notifyBucket()
		}
	}
	delete(s.streams, sid)

	if len(s.streams) == 0 && s.OnIdle != nil {
		s.OnIdle()
	}
}

// returnTokens is called by stream to return token after read
func (s *Session) returnTokens(n int) {
	if atomic.AddInt32(&s.bucket, int32(n)) > 0 {
		s.notifyBucket()
	}
}

// recvLoop keeps on reading from underlying connection if tokens are available
func (s *Session) recvLoop() {
	var hdr rawHeader
	var updHdr updHeader

	// Buffered + adaptive reads: see frame_reader.go. recvLoop is the
	// session's only reader of s.conn.
	br := newFrameReader(s.conn)
	defer br.release()

	for {
		// Wait until we have tokens or session is closed.
		for atomic.LoadInt32(&s.bucket) <= 0 && !s.IsClosed() {
			select {
			case <-s.bucketNotify:
			case <-s.die:
				// If it returns here, Accept() and OpenStream() are unblocked with io.ErrClosedPipe,
				// causing recvLoop to exit gracefully. If recvLoop is blocked in io.ReadFull, however,
				// it will be unblocked by a socket read error instead.
				return
			}
		}

		// As long as we have tokens, try to read frames.
		// read header first
		_, err := io.ReadFull(br, hdr[:])
		if err != nil {
			s.notifyReadError(err)
			return
		}

		// Mark the session as active
		atomic.StoreInt32(&s.sessionIsActive, 1)

		// validate protocol version
		if hdr.Version() != byte(s.config.Version) {
			s.notifyProtoError(ErrInvalidProtocol)
			return
		}

		// handle different command types
		sid := hdr.StreamID()
		switch hdr.Cmd() {
		case cmdNOP:
			if hdr.Length() != 0 {
				s.notifyProtoError(ErrInvalidProtocol)
				return
			}
		case cmdSYN: // stream opening
			if hdr.Length() != 0 {
				s.notifyProtoError(ErrInvalidProtocol)
				return
			}
			var accepted *stream
			s.streamLock.Lock()
			if _, ok := s.streams[sid]; !ok {
				stream := newStream(sid, s.config.MaxFrameSize, s)
				s.streams[sid] = stream
				accepted = stream
			}
			s.streamLock.Unlock()

			if accepted != nil {
				select {
				case s.chAccepts <- accepted:
				case <-s.die:
				}
			}

		case cmdFIN: // stream closing
			if hdr.Length() != 0 {
				s.notifyProtoError(ErrInvalidProtocol)
				return
			}
			s.streamLock.Lock()
			st := s.streams[sid]
			s.streamLock.Unlock()
			if st != nil {
				st.fin() // fin unblocks the readers and writers
			}

		case cmdPSH: // data frame
			if hdr.Length() == 0 {
				continue
			}

			// read payload from the underlying connection.
			// hdr.Length() is a uint16 wire field and the zero-length case is
			// filtered above, so the size is always within [1, 65535] —
			// pool.GetBuffer's poolable range. GetBuffer rounds up to the next
			// power-of-2 size class and returns a slice of len == Length, so
			// ReadFull reads exactly one frame payload. Pass the frame length
			// here, never the class size. The *[]byte head keeps the
			// full-capacity view: bufferRing reslices its working copy as data
			// is consumed, and only the head still carries cap == 2^n, which
			// pool.PutBuffer requires to recycle the buffer.
			buf := pool.GetBuffer(int(hdr.Length()))
			written, err := io.ReadFull(br, buf)
			if err != nil {
				s.notifyReadError(err)

				// recycle the buffer immediately.
				pool.PutBuffer(buf)
				return
			}

			// push data to the corresponding stream
			s.streamLock.Lock()
			if stream, ok := s.streams[sid]; ok {
				stream.pushBytes(&buf)
				// deduct tokens from the bucket
				atomic.AddInt32(&s.bucket, -int32(written))
				stream.wakeupReader()
			} else {
				// data directed to a missing/closed stream, recycle the buffer immediately.
				pool.PutBuffer(buf)
			}
			s.streamLock.Unlock()

		case cmdUPD: // a window update signal (v2 only)
			if s.config.Version != 2 {
				s.notifyProtoError(ErrInvalidProtocol)
				return
			}
			if hdr.Length() != szCmdUPD {
				s.notifyProtoError(ErrInvalidProtocol)
				return
			}

			_, err := io.ReadFull(br, updHdr[:])
			if err != nil {
				s.notifyReadError(err)
				return
			}

			// update the window size for the corresponding stream
			s.streamLock.Lock()
			st := s.streams[sid]
			s.streamLock.Unlock()
			if st != nil {
				st.update(updHdr.Consumed(), updHdr.Window())
			}

		default:
			s.notifyProtoError(ErrInvalidProtocol)
			return
		}
	}
}

// keepalive sends NOP frames periodically to keep the connection alive
func (s *Session) keepalive() {
	tickerPing := time.NewTicker(s.config.KeepAliveInterval)
	defer tickerPing.Stop()
	// KeepAliveTimeout == 0 disables the idle-kill: an smux v1 peer never
	// replies to NOP and is free to stay silent on an idle session, so "no
	// frame received" does not imply a dead link. NOP writes still probe the
	// link — a failed write tears the session down via notifyWriteError.
	var timeoutC <-chan time.Time
	if s.config.KeepAliveTimeout > 0 {
		tickerTimeout := time.NewTicker(s.config.KeepAliveTimeout)
		defer tickerTimeout.Stop()
		timeoutC = tickerTimeout.C
	}
	for {
		select {
		case <-tickerPing.C:
			s.writeFrameInternal(newFrame(byte(s.config.Version), cmdNOP, 0), tickerPing.C, CLSCTRL)
			s.notifyBucket() // force a wakeup signal to the recvLoop
		case <-timeoutC:
			if !atomic.CompareAndSwapInt32(&s.sessionIsActive, 1, 0) {
				// recvLoop may block while bucket is 0, in this case,
				// session should not be closed.
				if atomic.LoadInt32(&s.bucket) > 0 {
					s.Close()
					return
				}
			}
		case <-s.die:
			return
		}
	}
}

// shaperLoop implements a priority queue and bandwidth shaping for write requests.
// Eg: Control messages are prioritized over data messages, and shaper tries
// its best to keep fair bandwidth among streams.
func (s *Session) shaperLoop() {
	chShaper := s.shaper

	for {
		select {
		case <-s.die:
			return
		case r := <-chShaper:
			s.sq.Push(r)
			// batch drain: collect more requests if available
			for len(chShaper) > 0 && s.sq.Len() < maxShaperSize {
				select {
				case r := <-chShaper:
					s.sq.Push(r)
				default:
				}
			}
			// notify sendLoop there are pending requests
			s.notifyShaperPending()

			if s.sq.Len() >= maxShaperSize {
				// stop accepting new requests temporarily if shaper queue is full
				chShaper = nil
			}
		case <-s.chShaperConsumed:
			// re-enable shaper channel
			chShaper = s.shaper
		}
	}
}

// notifyShaperPending notifies sendLoop that there are pending requests
func (s *Session) notifyShaperPending() {
	select {
	case s.chShaperPending <- struct{}{}:
	default:
	}
}

// notifyShaperConsumed notifies when shaper queue is being consumed
func (s *Session) notifyShaperConsumed() {
	select {
	case s.chShaperConsumed <- struct{}{}:
	default:
	}
}

// sendLoop sends frames over the underlying connection
func (s *Session) sendLoop() {
	var n int
	var err error

	// getBufferWithRequestHeader builds a full frame (header+payload) in one
	// pooled buffer.
	getBufferWithRequestHeader := func(dataSize int, request writeRequest) []byte {
		buf := pool.GetBuffer(dataSize + headerSize)
		buf[0] = request.frame.ver
		buf[1] = request.frame.cmd
		binary.LittleEndian.PutUint16(buf[2:], uint16(len(request.frame.data)))
		binary.LittleEndian.PutUint32(buf[4:], request.frame.sid)
		return buf
	}

	// batch is reused across loop iterations: requests are drained, written
	// and their results delivered all within one iteration, so nothing
	// retains the slice past its reuse point.
	batch := make([]writeRequest, 0, maxWriteBatchFrames)

EVENT_LOOP:
	for {
		select {
		case <-s.die:
			return
		case <-s.chShaperPending:
			// Collect whatever is already queued: frames are self-delimiting
			// and TCP preserves order, so consecutive frames merge into ONE
			// underlying write. Bounds only cap syscall amortization; frames
			// still queued go out on the next round-trip, so merging adds no
			// latency of its own.
			batch = batch[:0]
			total := 0
			for {
				request, ok := s.sq.Pop()
				if !ok {
					break
				}
				batch = append(batch, request)
				total += headerSize + len(request.frame.data)
				if len(batch) >= maxWriteBatchFrames || total >= maxWriteBatchBytes {
					break
				}
			}
			if len(batch) == 0 {
				// notify shaperLoop to accept new requests
				s.notifyShaperConsumed()
				goto EVENT_LOOP
			}

			if len(batch) == 1 {
				// Fast path: a lone frame goes out as a single frame buffer.
				request := batch[0]
				buf := getBufferWithRequestHeader(len(request.frame.data), request)
				copy(buf[headerSize:], request.frame.data)
				n, err = s.conn.Write(buf)
				pool.PutBuffer(buf)
				n -= headerSize
				if n < 0 {
					n = 0
				}
				if err != nil {
					n = 0
				}
				request.result <- writeResult{n: n, err: err}
				if err != nil {
					s.notifyWriteError(err)
					return
				}
				continue
			}

			// Merged path: assemble the whole batch contiguously and issue a
			// single write. On success every frame is fully written; on error
			// the frames that fit (by cumulative offset) are credited and the
			// session is torn down by notifyWriteError, so unblocking the
			// rest via their waiters' chSocketWriteError select is enough.
			buf := pool.GetBuffer(total)
			off := 0
			for _, request := range batch {
				frame := buf[off : off+headerSize+len(request.frame.data)]
				frame[0] = request.frame.ver
				frame[1] = request.frame.cmd
				binary.LittleEndian.PutUint16(frame[2:], uint16(len(request.frame.data)))
				binary.LittleEndian.PutUint32(frame[4:], request.frame.sid)
				copy(frame[headerSize:], request.frame.data)
				off += len(frame)
			}
			n, err = s.conn.Write(buf[:total])
			pool.PutBuffer(buf)

			off = 0
			for _, request := range batch {
				payload := len(request.frame.data)
				rn := payload
				if err != nil {
					// credit only what fits before the failure point
					rn = n - off - headerSize
					if rn > payload {
						rn = payload
					}
					if rn < 0 {
						rn = 0
					}
				}
				off += headerSize + payload
				request.result <- writeResult{n: rn, err: err}
			}
			if err != nil {
				s.notifyWriteError(err)
				return
			}
		}
	}
}

// writeControlFrame writes the control frame to the underlying connection
// and returns the number of bytes written if successful
func (s *Session) writeControlFrame(f Frame) (n int, err error) {
	timer := time.NewTimer(openCloseTimeout)
	defer timer.Stop()

	return s.writeFrameInternal(f, timer.C, CLSCTRL)
}

// internal writeFrame version to support deadline used in keepalive
func (s *Session) writeFrameInternal(f Frame, deadline <-chan time.Time, class CLASSID) (int, error) {
	// get result channel from pool
	resultCh := resultChanPool.Get().(chan writeResult)

	req := writeRequest{
		class:  class,
		frame:  f,
		result: resultCh,
	}
	select {
	case s.shaper <- req:
	case <-s.die:
		resultChanPool.Put(resultCh)
		return 0, io.ErrClosedPipe
	case <-s.chSocketWriteError:
		resultChanPool.Put(resultCh)
		return 0, s.socketWriteError.Load().(error)
	case <-deadline:
		resultChanPool.Put(resultCh)
		return 0, ErrTimeout
	}

	select {
	case result := <-resultCh:
		resultChanPool.Put(resultCh)
		return result.n, result.err
	case <-s.die:
		// Cannot recycle channel here - sendLoop may still write to it
		return 0, io.ErrClosedPipe
	case <-s.chSocketWriteError:
		// Cannot recycle channel here - sendLoop may still write to it
		return 0, s.socketWriteError.Load().(error)
	case <-deadline:
		// Cannot recycle channel here - sendLoop may still write to it
		return 0, ErrTimeout
	}
}
