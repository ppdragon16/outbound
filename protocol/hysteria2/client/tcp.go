package client

import (
	"net"
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
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		// Read response
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, oops.Wrapf(err, "dial error: %s", msg)
		}
		c.Established = true
	}
	return c.Orig.Read(b)
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

func (c *tcpConn) SetDeadline(t time.Time) error {
	return c.Orig.SetDeadline(t)
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	return c.Orig.SetReadDeadline(t)
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}
