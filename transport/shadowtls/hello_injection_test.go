package shadowtls

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestSessionIDInjection proves the ClientHello that actually leaves the
// wire carries the HMAC-signed session id: a bare listener runs
// verifyClientHello against the first record it receives. This pins the
// utls integration — the handshake state must be built with
// BuildHandshakeState (not the ...WithoutSession variant) or the
// handshake silently rebuilds the hello and drops the injection.
func TestSessionIDInjection(t *testing.T) {
	const password = "injection-test"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	verified := make(chan error, 1)
	go func() {
		defer close(verified)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		frame, err := readFrame(c)
		if err != nil {
			verified <- err
			return
		}
		_, err = verifyClientHello(frame, []User{{Name: "u", Password: password}})
		verified <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// The listener closes after verifying, so NewConn fails with a read
	// error — that is expected; the assertion lives on the listener side.
	_, _ = NewConn(ctx, conn, Config{
		Password:      password,
		Version:       3,
		Sni:           "example.com",
		Fingerprint:   "chrome",
		AllowInsecure: true,
	})
	conn.Close()

	select {
	case err := <-verified:
		if err != nil {
			t.Fatalf("sent ClientHello failed verification: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("listener never verified the ClientHello")
	}
}
