package client

import (
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/pkg/oops"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/utils"
)

type tcpConn struct {
	Orig             *utils.QStream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool
	// deadlineMu serializes caller deadline changes with handshake
	// cleanup. Until the fast-open response is consumed, the dial
	// deadline caps both directions and cannot be extended by callers.
	deadlineMu    sync.Mutex
	dialDeadline  time.Time
	readDeadline  time.Time
	writeDeadline time.Time
	respErr       error
	establishOnce sync.Once
}

// handshakeDeadline returns the earlier nonzero deadline. Caller deadlines
// cannot extend or disable the dial timeout while the response is pending.
func (c *tcpConn) handshakeDeadline(t time.Time) time.Time {
	if !c.dialDeadline.IsZero() && (t.IsZero() || c.dialDeadline.Before(t)) {
		return c.dialDeadline
	}
	return t
}

func (c *tcpConn) readFastOpenResponse() error {
	c.establishOnce.Do(func() {
		defer func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			if !c.dialDeadline.IsZero() {
				// The response is consumed (or permanently failed):
				// drop the dial cap and hand the deadlines back to the
				// caller exactly as it set them.
				c.dialDeadline = time.Time{}
				_ = c.Orig.SetReadDeadline(c.readDeadline)
				_ = c.Orig.SetWriteDeadline(c.writeDeadline)
			}
		}()
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			c.respErr = err
			return
		}
		if !ok {
			c.respErr = oops.Wrapf(err, "dial error: %s", msg)
		}
	})
	return c.respErr
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		// Read response
		if err = c.readFastOpenResponse(); err != nil {
			return 0, err
		}
		c.Established = true
	}
	return c.Orig.Read(b)
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline, c.writeDeadline = t, t
	return c.Orig.SetDeadline(c.handshakeDeadline(t))
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	return c.Orig.SetReadDeadline(c.handshakeDeadline(t))
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	return c.Orig.SetWriteDeadline(c.handshakeDeadline(t))
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	return c.Orig.Write(b)
}

func (c *tcpConn) Close() error {
	return c.Orig.Close()
}

// CloseWrite signals end-of-stream to the hy2 server (half-close).
// Without this, dae's RelayTCP cannot tell the upstream "I'm done
// sending" when the local client closes its write side; it falls back
// to setting a 10s read deadline on the remote, which the relay's own
// 60-min per-iteration deadline race can overwrite — leaving the stream
// (and dae_active_connections gauge) pinned for up to an hour.
//
// quic.Stream.Close() closes only the send direction; the read side
// stays open so we can still drain the remote's remaining data.
// QStream.Close (the wrapper) intentionally does both, so we reach
// past it to the underlying quic.Stream.
func (c *tcpConn) CloseWrite() error {
	return c.Orig.Stream.Close()
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}
