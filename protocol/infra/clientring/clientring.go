// Package clientring provides the failover client ring shared by the QUIC
// based protocols (tuic, juicity): a circular list of live clients where a
// dial attempt walks to the next client on failover-class errors and spins
// up a new client when the ring is exhausted.
//
// The ring permit is held across dial attempts exactly as in the former
// per-protocol mutex rings (dials on one ring serialize, so only one
// connection triggers a QUIC handshake at a time). The difference is that a
// context-aware waiter blocked on the permit returns as soon as its context
// is done instead of queueing behind a handshake in progress, and that the
// per-node capability is an atomic written by quic-go's stream-table
// goroutine without touching the ring lock.
package clientring

import (
	"context"
	"errors"
	"sync/atomic"

	"golang.org/x/sync/semaphore"
)

// ErrRingClosed is returned by attempts racing a ring Close.
var ErrRingClosed = errors.New("client ring closed")

// capabilityCallback receives the live stream count reported by quic-go.
type capabilityCallback = func(n int64)

const initialRingCapacity = 4

// Node is one ring entry: the protocol client plus its last reported
// capability (-1 = unknown until the first capability report arrives).
type Node[T any] struct {
	Client     T
	capability atomic.Int64
}

// Capability returns the node's last reported capability (-1 = unknown).
func (n *Node[T]) Capability() int64 {
	if n == nil {
		return -1
	}
	return n.capability.Load()
}

// Ring is the shared failover ring. The protocol-specific dial bodies are
// supplied as attempt callbacks, so only client construction, close, and
// close-registration differ per protocol.
//
// The ring is backed by a circular buffer ([]*Node[T], head/tail indices)
// instead of container/list: the per-client Element allocation and the
// pointer-chasing walk are replaced by a flat, cache-friendly slice, at the
// cost of an O(n) shift on client removal (n is the number of live clients,
// a handful at most) and an amortized doubling copy when the buffer fills.
// Element identity - which the removal hook needs to survive growth - is
// kept by storing *Node[T] pointers.
type Ring[T any] struct {
	sem    *semaphore.Weighted
	closed bool

	buf  []*Node[T] // circular buffer; logical position i lives at buf[(head+i)%cap]
	head int
	len  int
	cur  int // logical position of the current client

	newClient  func(cb capabilityCallback) T
	setOnClose func(T, func())
	close      func(T) error
	reserved   int64
	// isFailoverErr reports whether err is one of the conditions the ring
	// treats as "try the next client" once every existing client has failed
	// (stream exhaustion, closed client, capability hold gate).
	isFailoverErr func(err error) bool
}

// New constructs a ring. newClient builds a client and wires its capability
// feedback to the given callback; setOnClose registers a ring-removal hook
// on a client; close tears one down. isFailoverErr classifies dial errors
// that justify walking to the next client.
func New[T any](
	newClient func(cb capabilityCallback) T,
	setOnClose func(T, func()),
	close func(T) error,
	reserved int64,
	isFailoverErr func(err error) bool,
) *Ring[T] {
	return &Ring[T]{
		sem:           semaphore.NewWeighted(1),
		buf:           make([]*Node[T], initialRingCapacity),
		newClient:     newClient,
		setOnClose:    setOnClose,
		close:         close,
		reserved:      reserved,
		isFailoverErr: isFailoverErr,
	}
}

// TryNext runs one dial attempt against the current client, walking the ring
// on failover-class errors and inserting a fresh client when every existing
// one failed.
func (r *Ring[T]) TryNext(f func(node *Node[T]) error) error {
	return r.TryNextContext(context.Background(), f)
}

// TryNextContext cancels the permit wait and stops further attempts when ctx
// ends. The callback is responsible for observing ctx during an active dial;
// a successful callback result is returned unchanged.
func (r *Ring[T]) TryNextContext(ctx context.Context, f func(node *Node[T]) error) error {
	if err := r.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer r.sem.Release(1)
	if r.closed {
		return ErrRingClosed
	}
	// Empty ring: construct the first client and attempt on it.
	if r.len == 0 {
		return r.getNew(ctx, f)
	}

	// Walk every live client once, starting at the current one.
	start := r.cur
	var err error
	for i := 0; i < r.len; i++ {
		if err = r.tryAt(ctx, (start+i)%r.len, f); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			// The caller gave up during this attempt: not a failover
			// condition, stop the walk here.
			return err
		}
	}

	// Clients are exhausted. A failover-class error spins up a fresh client
	// and retries on it; anything else is returned as-is.
	if !r.isFailoverErr(err) {
		return err
	}
	return r.getNew(ctx, f)
}

// tryAt runs one attempt against the client at logical position pos. A
// successful attempt makes that position current.
func (r *Ring[T]) tryAt(ctx context.Context, pos int, f func(*Node[T]) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	node := r.buf[(r.head+pos)%cap(r.buf)]
	err := f(node)
	if err == nil {
		r.cur = pos
	}
	return err
}

// getNew constructs a client, appends it at the logical tail (growing the
// backing buffer if it is full), makes it current, and runs the attempt on
// it. The setOnClose hook is registered with the new node's pointer, which
// stays stable across buffer growth.
func (r *Ring[T]) getNew(ctx context.Context, f func(*Node[T]) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.closed {
		return ErrRingClosed
	}
	if r.len == cap(r.buf) {
		r.grow()
	}
	node := &Node[T]{}
	node.capability.Store(-1)
	node.Client = r.newClient(func(n int64) { node.capability.Store(n) })
	r.setOnClose(node.Client, func() { r.passiveRemove(node) })
	r.buf[(r.head+r.len)%cap(r.buf)] = node
	r.cur = r.len
	r.len++
	return f(node)
}

// grow doubles the backing buffer, preserving logical order.
func (r *Ring[T]) grow() {
	newCap := cap(r.buf) * 2
	if newCap == 0 {
		newCap = initialRingCapacity
	}
	newBuf := make([]*Node[T], newCap)
	for i := 0; i < r.len; i++ {
		newBuf[i] = r.buf[(r.head+i)%cap(r.buf)]
	}
	r.buf = newBuf
	r.head = 0
}

// passiveRemove removes the node whose client force-closed itself. Called
// on the client's own teardown goroutine, possibly while a dial holds the
// permit: the acquire waits for that dial to finish (a bounded wait), so
// the hook must NOT fire synchronously from inside an attempt callback -
// that goroutine holds the permit and would self-deadlock.
func (r *Ring[T]) passiveRemove(node *Node[T]) {
	// Background acquire: there is no caller context to honor.
	if err := r.sem.Acquire(context.Background(), 1); err != nil {
		return
	}
	defer r.sem.Release(1)

	// Locate the node's logical position.
	pos := -1
	for i := 0; i < r.len; i++ {
		if r.buf[(r.head+i)%cap(r.buf)] == node {
			pos = i
			break
		}
	}
	if pos < 0 {
		return // already removed (e.g. by Close)
	}

	// Shift the followers back one slot (logical order preserved), then
	// clear the vacated tail slot.
	for i := pos + 1; i < r.len; i++ {
		r.buf[(r.head+i-1)%cap(r.buf)] = r.buf[(r.head+i)%cap(r.buf)]
	}
	last := (r.head + r.len - 1) % cap(r.buf)
	r.buf[last] = nil
	r.len--

	// Mirror the list semantics: removing the current element moves current
	// to the following client.
	if pos == r.cur {
		if r.cur >= r.len {
			r.cur = 0
		}
	} else if pos < r.cur {
		r.cur--
	}
	if r.len == 0 {
		r.cur = 0
		r.head = 0
	}
}

// Len returns the number of clients currently held in the ring.
func (r *Ring[T]) Len() int {
	if err := r.sem.Acquire(context.Background(), 1); err != nil {
		return 0
	}
	defer r.sem.Release(1)
	return r.len
}

// Close tears down every client in the ring. Each client is closed with the
// permit released, because client teardown fires the setOnClose hook, whose
// passiveRemove re-acquires the permit. All buffer manipulation happens
// under the permit; a hook firing during the released close window scans a
// consistent buf and finds its node already gone. The drain runs to
// completion no matter what: with a Background context the re-acquire
// cannot fail, but even if it did the remaining clients are still closed
// (best-effort, without the permit) rather than leaked.
func (r *Ring[T]) Close() error {
	if err := r.sem.Acquire(context.Background(), 1); err != nil {
		return err
	}
	r.closed = true

	held := true
	for r.len > 0 {
		idx := r.head
		node := r.buf[idx]
		r.buf[idx] = nil
		r.head = (r.head + 1) % cap(r.buf)
		r.len--
		if r.len == 0 {
			r.head, r.cur = 0, 0
		}
		if held {
			r.sem.Release(1)
		}
		_ = r.close(node.Client)
		if err := r.sem.Acquire(context.Background(), 1); err != nil {
			held = false // best-effort from here on, without exclusivity
		} else {
			held = true
		}
	}
	r.buf, r.head, r.len, r.cur = nil, 0, 0, 0
	if held {
		r.sem.Release(1)
	}
	return nil
}
