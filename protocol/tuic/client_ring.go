package tuic

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/infra/clientring"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

// clientRing is a thin facade over the shared infra ring, preserving the
// protocol-facing API (DialContextWithDialer / ListenPacketWithDialer /
// Close). The former hand-rolled mutex ring held its lock across the whole
// QUIC handshake on failover, blocking every new connection on the dialer
// for the duration; the shared ring waits on a context-aware semaphore
// permit instead, so a cancelled caller returns immediately.
type clientRing struct {
	ring     *clientring.Ring[*clientImpl]
	reserved int64
}

func newClientRing(newClient func(capabilityCallback func(n int64)) *clientImpl, reserved int64) *clientRing {
	return &clientRing{
		reserved: reserved,
		ring: clientring.New(
			newClient,
			func(cli *clientImpl, fn func()) { cli.setOnClose(fn) },
			func(cli *clientImpl) error { cli.Close(); return nil },
			reserved,
			isFailoverErr,
		),
	}
}

// isFailoverErr classifies the errors that justify walking to the next
// client once every existing client has been tried: stream exhaustion
// (matched by message, as quic-go surfaces it wrapped in transport errors),
// a closed client, or the capability hold gate.
func isFailoverErr(err error) bool {
	return errors.Is(err, common.ErrClientClosed) ||
		errors.Is(err, common.ErrHoldOn) ||
		strings.Contains(err.Error(), common.ErrTooManyOpenStreams.Error())
}

func (r *clientRing) DialContextWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (conn net.Conn, err error) {
	err = r.ring.TryNextContext(ctx, func(node *clientring.Node[*clientImpl]) error {
		if cap := node.Capability(); cap != -1 && cap <= r.reserved {
			return common.ErrHoldOn
		}
		conn, err = node.Client.DialContextWithDialer(ctx, metadata, dialer, dialFn)
		return err
	})
	return conn, err
}

func (r *clientRing) ListenPacketWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (conn net.PacketConn, err error) {
	err = r.ring.TryNextContext(ctx, func(node *clientring.Node[*clientImpl]) error {
		if cap := node.Capability(); cap != -1 && cap <= r.reserved {
			return common.ErrHoldOn
		}
		conn, err = node.Client.ListenPacketWithDialer(ctx, metadata, dialer, dialFn)
		return err
	})
	return conn, err
}

// Close closes all clientImpls in the ring and clears the ring.
// It is called when the parent Dialer is being permanently removed
// (e.g. via update-sub or daemon shutdown).
func (r *clientRing) Close() {
	_ = r.ring.Close()
}
