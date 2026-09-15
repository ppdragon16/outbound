package masque

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/quic-go/http3"
	utls "github.com/refraction-networking/utls"
)

// startHalfCloseH3Proxy runs a CONNECT proxy whose TCP handler echoes a
// fixed-size request and then keeps reading until the client half-closes.
// It signals on streamEOF when the server observes that FIN, and on
// serverDone when the handler returns.
func startHalfCloseH3Proxy(t *testing.T) (proxyAddr string, streamEOF <-chan struct{}) {
	t.Helper()
	streamEOFCh := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		str := w.(http3.HTTPStreamer).HTTPStream()
		// Echo exactly one fixed-size chunk, then keep reading: the
		// client's CloseWrite must surface here as an EOF, not as a
		// connection error, while the write direction back to the
		// client stays usable.
		req := make([]byte, 4)
		if _, err := io_ReadFull(str, req); err != nil {
			t.Logf("server: initial read: %v", err)
			close(streamEOFCh)
			return
		}
		t.Log("server: got ping, echoing pong")
		if _, err := str.Write([]byte("pong")); err != nil {
			close(streamEOFCh)
			return
		}
		buf := make([]byte, 512)
		for {
			if _, err := str.Read(buf); err != nil {
				close(streamEOFCh) // FIN observed
				// The peer's half-close must not have torn the stream
				// down: our write side is still open. Mirror it back.
				_, _ = str.Write([]byte("post-fin"))
				return
			}
		}
	})
	server := &http3.Server{
		Handler:   handler,
		TLSConfig: &utls.Config{Certificates: []utls.Certificate{selfSignedCert(t)}},
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close() })
	return pc.LocalAddr().String(), streamEOFCh
}

// io_ReadFull is io.ReadFull without colliding with the test file's imports.
func io_ReadFull(r interface{ Read([]byte) (int, error) }, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := r.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// TestTCPHalfClose pins the masque tcpConn's CloseWriter semantics: the
// quic-stream Close sends a FIN to the server while the local read side
// stays open, so post-FIN server data still arrives and the server sees
// the half-close instead of a hard cancel.
func TestTCPHalfClose(t *testing.T) {
	proxyAddr, streamEOF := startHalfCloseH3Proxy(t)
	client := newTestClient(t, proxyAddr)
	conn, err := client.DialContext(context.Background(), "tcp", "target.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cw, ok := conn.(netproxy.CloseWriter)
	if !ok {
		t.Fatal("masque tcpConn must implement netproxy.CloseWriter")
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	// Round-trip first: mirrors a real relay, where the half-close comes
	// after the traffic, not in the same flight as the last write.
	got := make([]byte, 4)
	if _, err := io_ReadFull(conn, got); err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if !bytes.Equal(got, []byte("pong")) {
		t.Fatalf("expected pong, got %q", got)
	}

	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// The server must observe the FIN (read EOF), not a stream cancel.
	select {
	case <-streamEOF:
	case <-time.After(10 * time.Second):
		t.Fatal("server never observed the half-close")
	}

	// The read side must survive our half-close: the server's write side
	// is still open and its mirrored write arrives after our FIN.
	got = make([]byte, 8)
	if _, err := io_ReadFull(conn, got); err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if !bytes.Equal(got, []byte("post-fin")) {
		t.Fatalf("expected post-fin, got %q", got)
	}
}
