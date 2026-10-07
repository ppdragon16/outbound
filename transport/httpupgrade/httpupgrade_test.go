package httpupgrade

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// staticConnDialer hands out one already-dialed conn, so the test can drive the
// upgrade handshake against a scripted peer.
type staticConnDialer struct{ conn net.Conn }

func (d *staticConnDialer) Alive() bool       { return true }
func (d *staticConnDialer) Connect() error    { return nil }
func (d *staticConnDialer) Disconnect() error { return nil }
func (d *staticConnDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}
func (d *staticConnDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

// TestDialContextKeepsBufferedUpgradePayload pins the buffered-bytes rule: the
// 101 response is read through a bufio window, so a peer that sends the
// response and the first payload bytes in one write leaves that payload
// buffered while the raw conn is drained. Returning the raw conn dropped it and
// desynchronized the upgraded session (the old TODO called this unreliable).
func TestDialContextKeepsBufferedUpgradePayload(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const payload = "UPGRADED-PAYLOAD"
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Drain the upgrade request, then answer with the 101 and the first
		// payload bytes in a single write.
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
		if _, err := c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n" + payload)); err != nil {
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

	d, err := NewDialer("httpupgrade://example.com:80/up?path=/up", &staticConnDialer{conn: clientEnd})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	// A deadline keeps the previous code's failure a test failure instead of a
	// hang: without the wrapper the payload sits in the discarded reader and
	// this read blocks until the peer closes.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read after upgrade: %v (want the buffered payload %q)", err, payload)
	}
	if string(got) != payload {
		t.Fatalf("read %q, want %q", got, payload)
	}
}
