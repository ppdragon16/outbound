package http

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// bannerProxyDialer hands the client one already-dialed conn, so the test can
// drive the CONNECT handshake against a scripted proxy.
type bannerProxyDialer struct{ conn net.Conn }

func (d *bannerProxyDialer) Alive() bool       { return true }
func (d *bannerProxyDialer) Connect() error    { return nil }
func (d *bannerProxyDialer) Disconnect() error { return nil }
func (d *bannerProxyDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}
func (d *bannerProxyDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

// TestConnectHandshakeKeepsBufferedBanner pins the buffered-bytes rule on the
// CONNECT path: the 200 response is read through a bufio window, so a proxy that
// answers with the status line and already-fetched bytes from a remote-first
// target (an SSH/SMTP banner) in one write leaves that payload buffered while
// rawConn is drained. Reading the raw conn afterwards dropped it and wedged the
// tunnel until an idle timeout.
func TestConnectHandshakeKeepsBufferedBanner(t *testing.T) {
	const banner = "SSH-2.0-dae-test\r\n"

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
		defer c.Close()
		// Drain the CONNECT request, then answer with the 200 and the banner in
		// a single write.
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n" + banner)); err != nil {
			return
		}
		// Hold the conn open so the client's read can drain.
		time.Sleep(2 * time.Second)
	}()

	clientEnd, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientEnd.Close()

	c := NewConn(&bannerProxyDialer{conn: clientEnd}, &HttpProxy{Addr: "proxy.invalid:8080"},
		"example.com:443", "tcp")
	// The CONNECT happens on the first write (the dial is lazy).
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// A deadline keeps the previous code's failure a test failure instead of a
	// hang: without the wrapper the banner sits in the discarded reader and this
	// read blocks until the peer closes.
	_ = clientEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(banner))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read after CONNECT: %v (want the buffered banner %q)", err, banner)
	}
	if string(got) != banner {
		t.Fatalf("read %q, want %q", got, banner)
	}
}
