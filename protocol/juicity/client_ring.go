package juicity

import (
	"container/list"
	"context"
	"errors"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

type clientRing struct {
	mu        sync.Mutex
	ring      *list.List
	current   *list.Element
	newClient func(capabilityCallback func(n int64)) *clientImpl
	reserved  int64
}

type clientRingNode struct {
	// capability is protected by quic RWMutex.
	capability int64
	cli        *clientImpl
}

func newClientRing(newClient func(capabilityCallback func(n int64)) *clientImpl, reserved int64) *clientRing {
	ring := list.New().Init()
	return &clientRing{
		mu:        sync.Mutex{},
		ring:      ring,
		current:   nil,
		newClient: newClient,
		reserved:  reserved,
	}
}

func (r *clientRing) DialContext(ctx context.Context, metadata *Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (conn *Conn, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	newCurrent := r.current
	err = r._tryNext(&newCurrent, func(node *clientRingNode) error {
		cap := node.capability
		if cap != -1 && cap <= r.reserved {
			return common.ErrHoldOn
		}
		conn, err = node.cli.DialContext(ctx, metadata, dialer, dialFn)
		return err
	})
	r.current = newCurrent
	return conn, err
}

func (r *clientRing) DialAuth(ctx context.Context, metadata *Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (iv []byte, psk []byte, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	newCurrent := r.current
	err = r._tryNext(&newCurrent, func(node *clientRingNode) error {
		cap := node.capability
		if cap != -1 && cap <= r.reserved {
			return common.ErrHoldOn
		}
		iv, psk, err = node.cli.DialAuth(ctx, metadata, dialer, dialFn)
		return err
	})
	r.current = newCurrent
	return iv, psk, err
}

func (r *clientRing) _tryNext(current **list.Element, f func(cli *clientRingNode) error) (err error) {
	var cli *clientRingNode
	if *current == nil {
		goto getNew
	}
	cli = (*current).Value.(*clientRingNode)
	err = f(cli)
	if err == nil {
		// OK.
		return nil
	}

	// Expected error: too many open streams.
	*current = (*current).Next()
	// NOTICE: Add the bellow code to reuse previous clients.
	{
		if *current == nil {
			*current = r.ring.Front()
		}
	}

	if *current == r.current {
		// Clients are exhausted.
		if errors.Is(err, common.ErrTooManyOpenStreams) ||
			errors.Is(err, common.ErrClientClosed) ||
			errors.Is(err, common.ErrHoldOn) {
			goto getNew
		}
		// Not the expected error.
		return err
	}

	return r._tryNext(current, f)

getNew:
	newNode := &clientRingNode{
		cli:        nil,
		capability: -1,
	}
	newCli := r.newClient(func(n int64) { newNode.capability = n })
	newNode.cli = newCli
	r.current = r._insertAfterCurrent(newNode)
	*current = r.current
	return f(newNode)
}

func (r *clientRing) _insertAfterCurrent(node *clientRingNode) (elem *list.Element) {
	if r.current == nil {
		elem = r.ring.PushBack(node)
		r.current = elem
	} else {
		elem = r.ring.InsertAfter(node, r.current)
	}
	node.cli.setOnClose(func() {
		r.passiveRemove(elem)
	})
	return elem
}

func (r *clientRing) passiveRemove(elem *list.Element) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if elem.Value == nil {
		// Removed.
		return
	}
	elem.Value = nil
	if r.current == elem {
		r.current = elem.Next()
	}
	r.ring.Remove(elem)
}

// Close closes all clientImpls in the ring and clears the ring.
// It is called when the parent Dialer is being permanently removed
// (e.g. via update-sub or daemon shutdown).
func (r *clientRing) Close() error {
	// Collect all clients under the lock, then release and close them
	// individually. We must NOT hold r.mu while calling cli.Close() because
	// clientImpl.Close() triggers detachCallback -> passiveRemove which
	// tries to acquire r.mu.
	r.mu.Lock()
	clients := make([]*clientImpl, 0, r.ring.Len())
	for elem := r.ring.Front(); elem != nil; {
		next := elem.Next()
		if node, ok := elem.Value.(*clientRingNode); ok && node != nil && node.cli != nil {
			clients = append(clients, node.cli)
		}
		elem.Value = nil
		r.ring.Remove(elem)
		elem = next
	}
	r.current = nil
	r.mu.Unlock()

	for _, cli := range clients {
		_ = cli.Close()
	}
	return nil
}
