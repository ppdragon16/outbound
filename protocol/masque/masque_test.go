package masque

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	"github.com/daeuniverse/quic-go/quicvarint"
	utls "github.com/refraction-networking/utls"
)

// selfSignedCert generates an in-memory ECDSA certificate.
func selfSignedCert(t testing.TB) utls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "masque-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"masque.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return utls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startH3Proxy serves a minimal MASQUE proxy: plain HTTP/3 CONNECT (TCP echo)
// and extended CONNECT for connect-udp (RFC 9298 datagram echo).
func startH3Proxy(t *testing.T) string { return startH3ProxyWithStatus(t, http.StatusOK) }

func startH3ProxyWithStatus(t *testing.T, connectStatus int) string {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Status must be written before taking the stream over: HTTPStream()
		// flushes, which implicitly commits 200 and swallows later codes.
		if connectStatus != http.StatusOK {
			w.WriteHeader(connectStatus)
			return
		}
		str := w.(http3.HTTPStreamer).HTTPStream()
		// A normal CONNECT keeps Proto "HTTP/3.0"; extended CONNECT carries
		// the :protocol value (RFC 8441 semantics as parsed by quic-go).
		if r.Proto != "HTTP/3.0" {
			w.WriteHeader(http.StatusOK)
			// drain the capsule stream so RESET/FIN state changes surface
			go func() {
				buf := make([]byte, 512)
				for {
					if _, err := str.Read(buf); err != nil {
						return
					}
				}
			}()
			for {
				buf, err := str.ReceiveDatagram(context.Background())
				if err != nil {
					return
				}
				contextID, consumed, err := quicvarint.Parse(buf)
				if err != nil || contextID != 0 {
					return
				}
				out := append(quicvarint.Append(nil, 0), buf[consumed:]...)
				if err := str.SendDatagram(out); err != nil {
					return
				}
			}
		}
		// plain CONNECT: echo the stream payload
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 2048)
		for {
			n, err := str.Read(buf)
			if n > 0 {
				if _, werr := str.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
	server := &http3.Server{
		Handler:         handler,
		TLSConfig:       &utls.Config{Certificates: []utls.Certificate{selfSignedCert(t)}},
		EnableDatagrams: true,
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close() })
	return pc.LocalAddr().String()
}

func readFull(t *testing.T, c io.Reader, b []byte) {
	t.Helper()
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("read %d bytes: %v", len(b), err)
	}
}

func newTestClient(t *testing.T, proxyAddr string, opts ...Option) *Client {
	t.Helper()
	client, err := NewClient(proxyAddr, "masque.test", true, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestTCPConnect(t *testing.T) {
	client := newTestClient(t, startH3Proxy(t))
	conn, err := client.DialContext(context.Background(), "tcp", "target.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// >16KiB forces multiple HTTP/3 DATA frames on the request stream
	payload := bytes.Repeat([]byte{'x'}, 40000)
	go func() {
		_, _ = conn.Write(payload)
	}()
	got := make([]byte, len(payload))
	readFull(t, conn, got)
	if !bytes.Equal(got, payload) {
		t.Fatal("tcp echo mismatch")
	}
}

func TestTCPUnsupportedNetwork(t *testing.T) {
	client := newTestClient(t, startH3Proxy(t))
	if _, err := client.DialContext(context.Background(), "udp", "target.example.com:443"); err == nil {
		t.Fatal("udp is not a DialContext network here")
	}
}

func TestUDPPacketConn(t *testing.T) {
	client := newTestClient(t, startH3Proxy(t))
	pc, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	targets := []*net.UDPAddr{
		{IP: net.ParseIP("8.8.8.8"), Port: 53},
		{IP: net.ParseIP("2001:db8::1"), Port: 443},
	}
	// each target gets its own CONNECT-UDP flow; labels prove the pairing
	want := make(map[string]string, len(targets))
	for i, target := range targets {
		payload := fmt.Sprintf("flow-%d-payload", i)
		want[target.String()] = payload
		if _, err := pc.WriteTo([]byte(payload), target); err != nil {
			t.Fatalf("write to %v: %v", target, err)
		}
	}
	got := make([]byte, 2048)
	for range targets {
		n, raddr, err := pc.ReadFrom(got)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		expect, ok := want[raddr.String()]
		if !ok {
			t.Fatalf("datagram from unexpected source %v", raddr)
		}
		if string(got[:n]) != expect {
			t.Fatalf("source %v returned %q, want %q", raddr, got[:n], expect)
		}
		delete(want, raddr.String())
	}
	if len(want) != 0 {
		t.Fatalf("missing datagrams from %v", want)
	}

	// a closed packet conn reports the closed state instead of hanging
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pc.ReadFrom(got); err == nil {
		t.Fatal("ReadFrom after Close must fail")
	}
}

// startUDPEchoProxyWithMaxStreams serves a CONNECT-UDP datagram echo with a
// deliberately tiny incoming-stream limit, so stream leaks exhaust it fast
// instead of after the default 100 streams.
func startUDPEchoProxyWithMaxStreams(t testing.TB, maxStreams int64) string {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Proto == "HTTP/3.0" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		str := w.(http3.HTTPStreamer).HTTPStream()
		w.WriteHeader(http.StatusOK)
		defer func() {
			str.CancelRead(0)
			_ = str.Close()
		}()
		for {
			buf, err := str.ReceiveDatagram(r.Context())
			if err != nil {
				return
			}
			contextID, consumed, err := quicvarint.Parse(buf)
			if err != nil || contextID != 0 {
				return
			}
			out := append(quicvarint.Append(nil, 0), buf[consumed:]...)
			if err := str.SendDatagram(out); err != nil {
				return
			}
		}
	})
	server := &http3.Server{
		Handler:         handler,
		TLSConfig:       &utls.Config{Certificates: []utls.Certificate{selfSignedCert(t)}},
		EnableDatagrams: true,
		QUICConfig:      &quic.Config{EnableDatagrams: true, MaxIncomingStreams: maxStreams},
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close() })
	return pc.LocalAddr().String()
}

// TestUDPFlowStreamsAreReclaimed pins the UDP flow teardown contract: a
// packetConn's CONNECT-UDP streams must be fully closed when it goes away. A
// RESET_STREAM on the send side alone leaves the stream open on the relay, so
// every closed flow kept occupying a slot in the peer's incoming-stream limit -
// after enough DNS queries through the tunnel, the limit was exhausted and
// every further dial blocked until its context expired.
func TestUDPFlowStreamsAreReclaimed(t *testing.T) {
	client := newTestClient(t, startUDPEchoProxyWithMaxStreams(t, 4))
	target := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	// Ten times the stream limit: only possible if closed flows are reclaimed.
	for i := 0; i < 10; i++ {
		t.Logf("round %d: listen", i)
		pc, err := client.ListenPacket(context.Background())
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		t.Logf("round %d: write", i)
		if _, err := pc.WriteTo([]byte(fmt.Sprintf("q%d", i)), target); err != nil {
			t.Fatalf("round %d write: %v", i, err)
		}
		t.Logf("round %d: read", i)
		pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		got := make([]byte, 512)
		if _, _, err := pc.ReadFrom(got); err != nil {
			t.Fatalf("round %d read: %v", i, err)
		}
		t.Logf("round %d: close", i)
		if err := pc.Close(); err != nil {
			t.Fatalf("round %d close: %v", i, err)
		}
	}
}

// TestPacketConnReadDeadline pins that datagram deadlines are real. They used
// to be silent no-ops, so a lost response blocked ReadFrom forever no matter
// what deadline the caller set.
func TestPacketConnReadDeadline(t *testing.T) {
	client := newTestClient(t, startH3Proxy(t))
	pc, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// No datagram will ever arrive (no flow is opened), so only the deadline
	// can end the read.
	pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	start := time.Now()
	_, _, err = pc.ReadFrom(make([]byte, 512))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want a deadline expiry", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("deadline was ignored: read returned after %v", elapsed)
	}
}

func BenchmarkPacketConnRoundTrip(b *testing.B) {
	client, err := NewClient(startUDPEchoProxyWithMaxStreams(b, 1024), "masque.test", true)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	pci, err := client.ListenPacket(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer pci.Close()
	pc := pci.(*packetConn)
	target := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	buf := make([]byte, 512)
	if err := pc.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pc.WriteToAddrPort([]byte("benchmark"), target.AddrPort()); err != nil {
			b.Fatal(err)
		}
		if _, _, err := pc.ReadFromAddrPort(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// TestPacketConnWriteDeadlineStillSends pins the timed-write path: dae's DNS
// upstream sets a deadline on every datagram write, so a write that carries a
// deadline must still go out (a regression here silently dropped the datagram
// and every DNS query through the tunnel timed out).
func TestPacketConnWriteDeadlineStillSends(t *testing.T) {
	client := newTestClient(t, startH3Proxy(t))
	pc, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	target := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}

	for i := 0; i < 3; i++ {
		if err := pc.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := pc.WriteTo([]byte(fmt.Sprintf("timed-%d", i)), target); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		got := make([]byte, 512)
		n, _, err := pc.ReadFrom(got)
		if err != nil {
			t.Fatalf("round %d: the datagram written under a deadline never arrived: %v", i, err)
		}
		if string(got[:n]) != fmt.Sprintf("timed-%d", i) {
			t.Fatalf("round %d echoed %q", i, got[:n])
		}
	}
}

func TestDatagramSizeLimit(t *testing.T) {
	client := newTestClient(t, startH3Proxy(t))
	pc, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo(make([]byte, maxDatagramSize+1), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}); err == nil {
		t.Fatal("oversized datagram must be rejected")
	}
}

// connCapture records the QUIC connections a test proxy accepted.
type connCapture struct {
	mu    sync.Mutex
	conns []quic.Connection
}

func (c *connCapture) add(q quic.Connection) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conns = append(c.conns, q)
}

func (c *connCapture) first(t *testing.T) quic.Connection {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.conns) == 0 {
		t.Fatal("no connection was accepted")
	}
	return c.conns[0]
}

// startEchoProxyCapturingConns serves a TCP echo CONNECT and records every
// accepted QUIC connection, so a test can kill the shared one.
func startEchoProxyCapturingConns(t *testing.T, capture *connCapture) string {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		str := w.(http3.HTTPStreamer).HTTPStream()
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 2048)
		for {
			n, err := str.Read(buf)
			if n > 0 {
				if _, werr := str.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
	server := &http3.Server{
		Handler:   handler,
		TLSConfig: &utls.Config{Certificates: []utls.Certificate{selfSignedCert(t)}},
		ConnContext: func(ctx context.Context, q quic.Connection) context.Context {
			capture.add(q)
			return ctx
		},
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close() })
	return pc.LocalAddr().String()
}

// TestDialRedialsAfterConnectionDies pins the reuse contract: the shared H3
// connection is reused across dials, but when it dies the next dial must
// establish a fresh one instead of failing on the cached dead connection
// forever.
func TestDialRedialsAfterConnectionDies(t *testing.T) {
	capture := &connCapture{}
	client := newTestClient(t, startEchoProxyCapturingConns(t, capture))

	echo := func(conn net.Conn, payload []byte) {
		t.Helper()
		go func() { _, _ = conn.Write(payload) }()
		got := make([]byte, len(payload))
		readFull(t, conn, got)
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo = %q, want %q", got, payload)
		}
	}

	before, err := client.DialContext(context.Background(), "tcp", "target.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	echo(before, []byte("before"))
	_ = before.Close()

	// Kill the shared connection from the server side and wait until the
	// client has observed it.
	q := capture.first(t)
	if err := q.CloseWithError(0, "test"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		client.mu.Lock()
		qconn := client.qconn
		client.mu.Unlock()
		if qconn != nil && qconn.Context().Err() != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client did not observe the closed connection")
		}
		time.Sleep(10 * time.Millisecond)
	}

	after, err := client.DialContext(context.Background(), "tcp", "target.example.com:443")
	if err != nil {
		t.Fatalf("dial after the shared connection died: %v", err)
	}
	defer after.Close()
	echo(after, []byte("after"))
}

func TestConnectRejected(t *testing.T) {
	// The default dial is optimistic, so the proxy's rejection is validated on
	// the first read rather than at dial time.
	client := newTestClient(t, startH3ProxyWithStatus(t, http.StatusForbidden))
	conn, err := client.DialContext(context.Background(), "tcp", "blocked.example.com:443")
	if err != nil {
		return // also acceptable: the stream was reset before validation
	}
	defer conn.Close()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a rejected CONNECT must surface on the first read")
	}
}

// TestZeroRTTDialIsStillOptimistic pins that the 0-RTT option must not cost
// the optimistic dial: a link with zero_rtt=1 used to fall back to the strict
// dial (waiting for the proxy's CONNECT response, which only arrives after the
// target dial), adding a full round trip to every measured latency.
func TestZeroRTTDialIsStillOptimistic(t *testing.T) {
	const delay = 500 * time.Millisecond
	client := newTestClient(t, startDelayedH3Proxy(t, delay), WithZeroRTT())

	start := time.Now()
	conn, err := client.DialContext(context.Background(), "tcp", "target.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if elapsed := time.Since(start); elapsed >= delay/2 {
		t.Fatalf("dial with zero_rtt waited for the CONNECT response: took %v while the proxy delays it by %v", elapsed, delay)
	}
}

func TestConnectRejectedStrict(t *testing.T) {
	client := newTestClient(t, startH3ProxyWithStatus(t, http.StatusForbidden), WithStrictConnect())
	if _, err := client.DialContext(context.Background(), "tcp", "blocked.example.com:443"); err == nil {
		t.Fatal("rejected CONNECT must return a dial error in strict mode")
	}
}

// startDelayedH3Proxy serves a TCP echo CONNECT whose response is only written
// after delay, mimicking a proxy that dials the target before answering.
func startDelayedH3Proxy(t *testing.T, delay time.Duration) string {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		time.Sleep(delay)
		str := w.(http3.HTTPStreamer).HTTPStream()
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 2048)
		for {
			n, err := str.Read(buf)
			if n > 0 {
				if _, werr := str.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
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
	return pc.LocalAddr().String()
}

// TestOptimisticDialDoesNotWaitForResponse pins the latency property: the
// CONNECT response only arrives after the proxy has dialed the target, so
// waiting for it makes every dial cost two round trips (handshake + CONNECT).
// The dial must return as soon as the request is sent, with the status
// validated on first read.
func TestOptimisticDialDoesNotWaitForResponse(t *testing.T) {
	const delay = 500 * time.Millisecond
	client := newTestClient(t, startDelayedH3Proxy(t, delay))

	start := time.Now()
	conn, err := client.DialContext(context.Background(), "tcp", "target.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	elapsed := time.Since(start)
	if elapsed >= delay/2 {
		t.Fatalf("dial waited for the CONNECT response: took %v while the proxy delays it by %v", elapsed, delay)
	}

	// The tunnel still works once the response arrives.
	payload := bytes.Repeat([]byte{'y'}, 4096)
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, len(payload))
	readFull(t, conn, got)
	if !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch through an optimistic dial")
	}
}

// TestPacketConnDialerOverride stacks MASQUE on an externally supplied UDP
// packet conn routed through a local relay, proving the injection point works.
func TestPacketConnDialerOverride(t *testing.T) {
	backend := startH3Proxy(t)
	relayAddr := startUDPRelay(t, backend)
	var injected atomic.Bool
	client := newTestClient(t, relayAddr, WithPacketConnDialer(func(ctx context.Context, addr string) (net.PacketConn, error) {
		injected.Store(true)
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	}))

	const payload = "through-relay"
	conn, err := client.DialContext(context.Background(), "tcp", "relayed.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	readFull(t, conn, got)
	if string(got) != payload {
		t.Fatalf("got %q", got)
	}
	if !injected.Load() {
		t.Fatal("custom packet conn dialer was not used")
	}
}

// startUDPRelay forwards datagrams between a local socket and dstAddr.
func startUDPRelay(t *testing.T, dstAddr string) string {
	t.Helper()
	dst, err := net.ResolveUDPAddr("udp", dstAddr)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		var clientAddr *net.UDPAddr
		for {
			n, from, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if from.String() == dst.String() {
				if clientAddr != nil {
					_, _ = ln.WriteToUDP(buf[:n], clientAddr)
				}
				continue
			}
			clientAddr = from
			_, _ = ln.WriteToUDP(buf[:n], dst)
		}
	}()
	return ln.LocalAddr().String()
}

// startUDPBlackhole returns a UDP address and a channel delivering the first
// datagram a client sends to it, so the QUIC version of the initial packet can
// be asserted without completing a handshake.
func startUDPBlackhole(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	pktCh := make(chan []byte, 4)
	go func() {
		for {
			buf := make([]byte, 4096)
			n, _, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case pktCh <- pkt:
			default:
			}
		}
	}()
	return pc.LocalAddr().String(), pktCh
}

// TestQuicVersionPreference pins the outbound negotiation behaviour: by
// default the first packet is QUIC v1, and WithQuicV2 flips it to RFC 9369 v2
// (0x6b3343cf) while keeping v1 for fallback.
func TestQuicVersionPreference(t *testing.T) {
	for _, tc := range []struct {
		name       string
		preferV2   bool
		wantPrefix uint32
	}{
		{"default offers v1", false, 0x1},
		{"preferV2 offers v2", true, 0x6b3343cf},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, pktCh := startUDPBlackhole(t)
			client := newTestClient(t, addr, WithQuicV2(tc.preferV2))
			ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
			defer cancel()
			// The blackhole never answers, so the dial fails; the first flight
			// it emits is what matters here.
			_, _ = client.DialContext(ctx, "tcp", "unreachable.example.com:443")

			select {
			case pkt := <-pktCh:
				if len(pkt) < 5 {
					t.Fatal("short packet")
				}
				got := uint32(pkt[1])<<24 | uint32(pkt[2])<<16 | uint32(pkt[3])<<8 | uint32(pkt[4])
				if got != tc.wantPrefix {
					t.Fatalf("first packet version = %#x, want %#x", got, tc.wantPrefix)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no packet captured")
			}
		})
	}
}

func TestUDPPathEncoding(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"8.8.8.8", 443, "/.well-known/masque/udp/8.8.8.8/443/"},
		{"2001:db8::1", 443, "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/"},
		{"proxy.blue.c", 53, "/.well-known/masque/udp/proxy.blue.c/53/"},
	}
	for _, tc := range cases {
		if got := udpPath(tc.host, tc.port); got != tc.want {
			t.Errorf("udpPath(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}
