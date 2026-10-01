package http

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// silentProxyDialer hands out a conn whose peer drains writes and never answers,
// like a proxy that accepts the TCP connection and then goes silent.
type silentProxyDialer struct{ conn net.Conn }

func (d *silentProxyDialer) Alive() bool       { return true }
func (d *silentProxyDialer) Connect() error    { return nil }
func (d *silentProxyDialer) Disconnect() error { return nil }
func (d *silentProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.conn, nil
}
func (d *silentProxyDialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

// TestConnectHandshakeIsBounded pins the handshake budget. DialContext is lazy
// (the CONNECT happens on the first write) and ignores the caller's context, so
// without a deadline on the exchange a proxy that accepts TCP and stays silent
// wedged the first write forever — and with it the connectivity check that
// issued it.
func TestConnectHandshakeIsBounded(t *testing.T) {
	old := httpConnectHandshakeTimeout
	httpConnectHandshakeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { httpConnectHandshakeTimeout = old })

	// A real loopback pair: net.Pipe does not honour deadlines, and the whole
	// point of this test is the deadline.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// Drain the CONNECT request; never answer it.
		_, _ = io.Copy(io.Discard, c)
	}()
	clientEnd, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientEnd.Close()

	c := NewConn(&silentProxyDialer{conn: clientEnd}, &HttpProxy{Addr: "proxy.invalid:8080"},
		"example.com:443", "tcp")

	done := make(chan error, 1)
	go func() {
		// Not an HTTP request line: this takes the CONNECT path.
		_, err := c.Write([]byte("not-an-http-request"))
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Write reported success although the proxy never answered CONNECT")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CONNECT handshake was not bounded: the first write hung without a deadline")
	}
}
