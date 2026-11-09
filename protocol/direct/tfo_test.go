package direct

import (
	"context"
	"net"
	"testing"
	"time"
)

// TFO dials must still work end-to-end on kernels without a TFO cookie for
// the peer (and peers without TFO at all): TCP_FASTOPEN_CONNECT falls back to
// a regular handshake, so the first write either rides the SYN or follows it.
func TestTfoDialerFallbackConnectivity(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("listen:", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 1)
				if n, err := c.Read(buf); n == 1 && err == nil {
					_, _ = c.Write([]byte{buf[0] + 1})
				}
			}()
		}
	}()

	d := NewDirectDialer(Option{TFO: true})
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{7}); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil || buf[0] != 8 {
		t.Fatalf("read: %v buf=%v", err, buf)
	}
}
