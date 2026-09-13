package anytls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

// ---------------------------------------------------------------------------
// Test harness: a minimal anytls server speaking the wire format directly.
// ---------------------------------------------------------------------------

func testReadFrame(conn net.Conn) (cmd byte, sid uint32, payload []byte, err error) {
	var hdr [7]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	cmd = hdr[0]
	sid = binary.BigEndian.Uint32(hdr[1:5])
	length := int(binary.BigEndian.Uint16(hdr[5:7]))
	payload = make([]byte, length)
	if length > 0 {
		_, err = io.ReadFull(conn, payload)
	}
	return
}

func testWriteFrame(conn net.Conn, cmd byte, sid uint32, payload []byte) error {
	buf := make([]byte, 7+len(payload))
	buf[0] = cmd
	binary.BigEndian.PutUint32(buf[1:5], sid)
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(payload)))
	copy(buf[7:], payload)
	_, err := conn.Write(buf)
	return err
}

// testServer accepts TCP+TLS connections, consumes the 34-byte key exchange
// prefix, and hands each established TLS conn to the test via Accept.
type testServer struct {
	ln     net.Listener
	accept chan net.Conn
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"example.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts := &testServer{ln: ln, accept: make(chan net.Conn, 4)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(ts.accept)
				return
			}
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err := tc.Handshake(); err != nil {
				_ = tc.Close()
				continue
			}
			// Consume the key exchange prefix: 32-byte key + 2 zero bytes.
			if _, err := io.ReadFull(tc, make([]byte, 34)); err != nil {
				_ = tc.Close()
				continue
			}
			ts.accept <- tc
		}
	}()
	return ts
}

// Accept waits for a new TCP+TLS connection, failing the test on timeout so a
// stuck test reports the point of deadlock instead of hanging forever.
func (ts *testServer) Accept(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-ts.accept:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a new TLS connection")
		return nil
	}
}

// NoNewConn asserts that the server sees no additional TCP connection within
// a short window — i.e. the client reused the existing session.
func (ts *testServer) NoNewConn(t *testing.T) {
	t.Helper()
	select {
	case <-ts.accept:
		t.Fatal("client unexpectedly opened a new TLS connection")
	case <-time.After(300 * time.Millisecond):
	}
}

// frameEvent is a "significant" frame the test assertions care about;
// padding, settings, and heartbeats are handled transparently.
type frameEvent struct {
	cmd     byte
	sid     uint32
	payload []byte
}

// serverNextEvent reads frames from the client until a significant one
// (SYN/PSH/FIN) arrives. Waste padding and Settings are skipped, and
// HeartRequests (checkout probe + background heartbeat) are answered on the
// spot, since the client only consumes their responses inside Read.
func serverNextEvent(t *testing.T, conn net.Conn) frameEvent {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	for {
		cmd, sid, payload, err := testReadFrame(conn)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		switch cmd {
		case cmdWaste, cmdSettings, cmdUpdatePaddingScheme, cmdServerSettings, cmdAlert:
			continue
		case cmdHeartRequest:
			if err := testWriteFrame(conn, cmdHeartResponse, sid, nil); err != nil {
				t.Fatal(err)
			}
			continue
		}
		return frameEvent{cmd: cmd, sid: sid, payload: payload}
	}
}

// newSessionAsConnDialer builds a session-as-conn dialer against proxyAddr.
// It constructs Dialer directly (same package) so tests run deterministically:
// minIdleSession=0 disables background replenishment (NewDialer would always
// apply a positive default and open connections behind the test's back) and
// heartbeatInterval=0 silences the heartbeat goroutine.
func newSessionAsConnDialer(t *testing.T, proxyAddr string) netproxy.Dialer {
	t.Helper()
	sum := sha256.Sum256([]byte("testpass"))
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: direct.NewDirectDialer(direct.Option{}),
		},
		proxyAddress:             proxyAddr,
		key:                      sum[:],
		tlsConfig:                &utls.Config{ServerName: "example.com", InsecureSkipVerify: true},
		sessions:                 make(map[uint64]*session),
		idleSessions:             make(map[uint64]*session),
		sessionAsConn:            true,
		minIdleSession:           0,
		idleSessionCheckInterval: 200 * time.Millisecond, // NewTicker requires > 0
		idleSessionTimeout:       time.Hour,              // no reaping during a test
		ctx:                      ctx,
		cancel:                   cancel,
	}
	go d.idleCleanupLoop()
	t.Cleanup(func() { cancel(); _ = d.Disconnect() })
	return d
}

// waitPool waits for the async pool return: sessionConn.Close hands the
// session back via closeStreamChan, and manageSession (a separate goroutine)
// performs the actual bookkeeping, so an immediately following dial may race
// the return. Real callers have inter-request gaps; tests must wait.
func waitPool(t *testing.T, d netproxy.Dialer, want int) {
	t.Helper()
	dd := d.(*Dialer)
	for i := 0; i < 500; i++ {
		dd.mu.Lock()
		n := len(dd.idleSessions)
		dd.mu.Unlock()
		if n >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("session never returned to the idle pool (want %d)", want)
}

// expectRead reads from conn until n bytes are collected or the test times out.
func expectRead(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	if _, err := io.ReadFull(conn, out); err != nil {
		t.Fatalf("expectRead %d bytes: %v", n, err)
	}
	return out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestSessionAsConnBasicAndReuse covers the whole happy path of one dial:
// SYN/PSH(addr) opening, data both ways, padding frames interleaved on the
// receive path, server FIN -> EOF, close returning the session to the pool,
// checkout probe (heartbeat), and reuse of the same TLS connection for a
// second request with a new stream id.
func TestSessionAsConnBasicAndReuse(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", "target.example.com:80")
	if err != nil {
		t.Fatal(err)
	}

	tc := ts.Accept(t)

	// First request: batched settings+SYN+PSH(addr), sid=1.
	ev := serverNextEvent(t, tc)
	if ev.cmd != cmdSYN || ev.sid != 1 {
		t.Fatalf("expected SYN sid=1, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	ev = serverNextEvent(t, tc)
	if ev.cmd != cmdPSH || !bytes.Contains(ev.payload, []byte("target.example.com")) {
		t.Fatalf("expected PSH carrying the socks addr, got cmd=%d payload=%q", ev.cmd, ev.payload)
	}

	// Server responds: padding, data, padding, data, FIN.
	if err := testWriteFrame(tc, cmdWaste, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := testWriteFrame(tc, cmdWaste, 0, make([]byte, 13)); err != nil {
		t.Fatal(err)
	}
	if err := testWriteFrame(tc, cmdPSH, 1, []byte("hello ")); err != nil {
		t.Fatal(err)
	}
	if err := testWriteFrame(tc, cmdPSH, 1, []byte("anytls")); err != nil {
		t.Fatal(err)
	}
	if err := testWriteFrame(tc, cmdFIN, 1, nil); err != nil {
		t.Fatal(err)
	}

	// Read hands out one frame payload per call — loop to drain.
	buf := make([]byte, 32)
	var got bytes.Buffer
	for {
		n, err := conn.Read(buf)
		got.Write(buf[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if got.String() != "hello anytls" {
		t.Fatalf("read %q, want %q", got.String(), "hello anytls")
	}

	// Client -> server data.
	if _, err := conn.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	ev = serverNextEvent(t, tc)
	if ev.cmd != cmdPSH || string(ev.payload) != "PING" {
		t.Fatalf("expected PSH PING, got cmd=%d payload=%q", ev.cmd, ev.payload)
	}

	// The server already sent FIN, so Close sends no FIN of its own; the
	// session returns to the pool.
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	// Second dial must reuse the same TLS connection (checkout probe and
	// heartbeat are answered transparently by serverNextEvent).
	waitPool(t, d, 1)
	conn2, err := d.DialContext(ctx, "tcp", "target.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	ev = serverNextEvent(t, tc)
	if ev.cmd != cmdSYN || ev.sid != 2 {
		t.Fatalf("expected SYN sid=2 on reused session, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	if err := testWriteFrame(tc, cmdPSH, 2, []byte("second")); err != nil {
		t.Fatal(err)
	}
	n, err := conn2.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "second" {
		t.Fatalf("read %q, want %q", buf[:n], "second")
	}
	ts.NoNewConn(t)
	_ = conn2.Close()
}

// TestSessionAsConnStaleDataIsolation verifies that in-flight data of a
// previous request (older sid) still arriving after the session was returned
// to the pool and checked out again is dropped, not delivered to the new
// request. This is what makes pool reuse safe without the run() loop.
func TestSessionAsConnStaleDataIsolation(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn1, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc := ts.Accept(t)
	if ev := serverNextEvent(t, tc); ev.cmd != cmdSYN || ev.sid != 1 {
		t.Fatalf("expected SYN sid=1, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	if ev := serverNextEvent(t, tc); ev.cmd != cmdPSH {
		t.Fatalf("expected PSH addr, got cmd=%d", ev.cmd)
	}
	if err := testWriteFrame(tc, cmdPSH, 1, []byte("resp1")); err != nil {
		t.Fatal(err)
	}
	if err := testWriteFrame(tc, cmdFIN, 1, nil); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := conn1.Read(buf); err != nil {
		t.Fatal(err)
	}
	_ = conn1.Close()
	waitPool(t, d, 1)

	// Second request on the reused session. Before its data, the server
	// "leaks" late bytes of the first stream (stale PSH arrives while the
	// checkout probe is answered transparently).
	conn2, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	if err := testWriteFrame(tc, cmdPSH, 1, []byte("STALE")); err != nil {
		t.Fatal(err)
	}
	// Close sends our FIN (server FIN above was never consumed by the client).
	if ev := serverNextEvent(t, tc); ev.cmd != cmdFIN || ev.sid != 1 {
		t.Fatalf("expected client FIN sid=1, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	ev := serverNextEvent(t, tc)
	if ev.cmd != cmdSYN || ev.sid != 2 {
		t.Fatalf("expected SYN sid=2, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	if err := testWriteFrame(tc, cmdPSH, 2, []byte("fresh")); err != nil {
		t.Fatal(err)
	}

	n, err := conn2.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "fresh" {
		t.Fatalf("stale data leaked into new request: got %q, want %q", buf[:n], "fresh")
	}
	_ = conn2.Close()
}

// TestSessionAsConnLargePayload covers payload reassembly: a payload read
// directly into a large caller buffer (fast path) and one much larger than
// the caller buffer, handed out in slices from a pending pool buffer.
func TestSessionAsConnLargePayload(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc := ts.Accept(t)
	// Skip SYN + PSH(addr).
	serverNextEvent(t, tc)
	serverNextEvent(t, tc)

	pattern := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i % 251)
		}
		return b
	}

	// Case 1: 8 KiB payload, 16 KiB caller buffer — single fast-path read.
	small := pattern(8 << 10)
	if err := testWriteFrame(tc, cmdPSH, 1, small); err != nil {
		t.Fatal(err)
	}
	big1 := make([]byte, 16<<10)
	n, err := conn.Read(big1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(big1[:n], small) {
		t.Fatalf("fast-path payload mismatch: got %d bytes", n)
	}

	// Case 2: 40 KiB payload, 5 KiB caller buffer — pending path, 8 reads.
	large := pattern(40 << 10)
	if err := testWriteFrame(tc, cmdPSH, 1, large); err != nil {
		t.Fatal(err)
	}
	if err := testWriteFrame(tc, cmdFIN, 1, nil); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	chunk := make([]byte, 5<<10)
	for {
		n, err := conn.Read(chunk)
		got.Write(chunk[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), large) {
		t.Fatalf("pending-path payload mismatch: got %d bytes, want %d", got.Len(), len(large))
	}
}

// TestSessionAsConnReadDeadline verifies deadline transparency: a deadline
// expiring mid-idle fails the read with a timeout, and clearing it lets a
// later read succeed (the connection is not poisoned).
func TestSessionAsConnReadDeadline(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc := ts.Accept(t)
	serverNextEvent(t, tc)
	serverNextEvent(t, tc)

	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected timeout error")
	} else {
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			t.Fatalf("expected timeout error, got %v", err)
		}
	}

	// A timed-out Read marks the conn permanently unusable: the frame
	// stream may sit mid-header or mid-payload, so retrying is not merely
	// pointless, it would parse payload bytes as a frame header. The error
	// surfaces as net.ErrClosed regardless of what the deadline cleared.
	if err := testWriteFrame(tc, cmdPSH, 1, []byte("late")); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after a timed-out read, got %v", err)
	}
}

// TestSessionAsConnStreamRefused verifies the SYNACK error path: a server
// refusal of the stream surfaces as a Read error.
func TestSessionAsConnStreamRefused(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc := ts.Accept(t)
	serverNextEvent(t, tc)
	serverNextEvent(t, tc)
	if err := testWriteFrame(tc, cmdSYNACK, 1, []byte("target unreachable")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected stream-refused error")
	} else if !bytes.Contains([]byte(err.Error()), []byte("target unreachable")) {
		t.Fatalf("error should carry server message, got %v", err)
	} else if !errors.Is(err, ErrStreamRefused) {
		t.Fatalf("expected ErrStreamRefused sentinel, got %v", err)
	}

	// The refusal is application-level: the frame stream stays aligned, so
	// the session must return to the idle pool instead of being killed.
	_ = conn.Close()
	waitPool(t, d, 1)

	// The next request reuses the SAME session (no new TCP conn): the mock
	// server answers on tc, including the stale FIN for sid=1 that the
	// server sent when it closed the refused stream.
	conn2, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	// The abandoned conn's Close already wrote FIN(sid=1) before pooling.
	if ev := serverNextEvent(t, tc); ev.cmd != cmdFIN || ev.sid != 1 {
		t.Fatalf("expected client FIN sid=1, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	if ev := serverNextEvent(t, tc); ev.cmd != cmdSYN || ev.sid != 2 {
		t.Fatalf("expected reused session with SYN sid=2, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	if err := testWriteFrame(tc, cmdFIN, 1, nil); err != nil {
		t.Fatal(err) // stale FIN of the refused stream, skipped by sid filter
	}
	if err := testWriteFrame(tc, cmdPSH, 2, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	n, err := conn2.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("read %q, want %q", buf[:n], "hello")
	}
	_ = conn2.Close()
}

// TestSessionAsConnUDPUsesDedicatedSession verifies that in session-as-conn
// mode ListenPacket creates its own stream-path session (a new TLS
// connection) and does NOT return it to the idle pool: the next TCP dial
// still reuses the first session (next sid), not the UDP one.
func TestSessionAsConnUDPUsesDedicatedSession(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	// First: a plain TCP dial establishes session #1.
	conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc1 := ts.Accept(t)
	if ev := serverNextEvent(t, tc1); ev.cmd != cmdSYN || ev.sid != 1 {
		t.Fatalf("expected SYN sid=1, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	if ev := serverNextEvent(t, tc1); ev.cmd != cmdPSH {
		t.Fatalf("expected PSH addr, got cmd=%d", ev.cmd)
	}
	if err := testWriteFrame(tc1, cmdPSH, 1, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	// UDP: must open a second, dedicated TLS connection (stream path with
	// run() loop for fan-in).
	pc, err := d.ListenPacket(ctx, "8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}
	tc2 := ts.Accept(t)
	if ev := serverNextEvent(t, tc2); ev.cmd != cmdSYN || ev.sid != 1 {
		t.Fatalf("expected SYN sid=1 on dedicated UDP session, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	if ev := serverNextEvent(t, tc2); ev.cmd != cmdPSH {
		t.Fatalf("expected PSH packet addr, got cmd=%d", ev.cmd)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}

	// Another TCP dial: reuses session #1 (probe + SYN sid=2), never the
	// UDP session — proving the UDP session never entered the idle pool.
	waitPool(t, d, 1)
	conn3, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	// conn.Close() sent our FIN (no server FIN was consumed on this conn).
	if ev := serverNextEvent(t, tc1); ev.cmd != cmdFIN || ev.sid != 1 {
		t.Fatalf("expected client FIN sid=1, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	if ev := serverNextEvent(t, tc1); ev.cmd != cmdSYN || ev.sid != 2 {
		t.Fatalf("expected SYN sid=2 on first session, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	ts.NoNewConn(t)
	_ = conn3.Close()
}

// TestSessionAsConnInterruptKillsSession reproduces the production failure
// behind "anytls: invalid cmd": dae's relayCore forceClose sets a past read
// deadline (interrupting a Read mid-frame) and then calls Close. The
// session's stream position can no longer be trusted, so it must be killed
// instead of returning to the idle pool, where the next request would read a
// shifted frame stream.
func TestSessionAsConnInterruptKillsSession(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc := ts.Accept(t)
	clientHandshake(t, tc)

	// Server sends a 16 KiB payload; the client reads only the first 100
	// bytes, drains the cached remainder, and then a past deadline
	// interrupts the next Read while it waits on a frame header.
	payload := make([]byte, 16<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := testWriteFrame(tc, cmdPSH, 1, payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	for {
		// Short deadline: buffered payload bytes come back instantly (copies
		// don't consult the deadline); waiting on the next frame header
		// times out.
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := conn.Read(make([]byte, 32<<10)); err != nil {
			break
		}
	}
	// forceClose's past deadline: the next Read blocks on the frame header
	// of whatever the server sends next and gets interrupted.
	_ = conn.SetReadDeadline(time.Unix(1, 0))
	if _, err := conn.Read(make([]byte, 32<<10)); err == nil {
		t.Fatal("expected the interrupted Read to return an error")
	}
	_ = conn.Close() // forceClose calls Close while the relay unwinds

	// The poisoned session must never re-enter the idle pool: the next dial
	// has to open a brand-new TLS connection.
	conn2, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc2 := ts.Accept(t)
	if ev := serverNextEvent(t, tc2); ev.cmd != cmdSYN || ev.sid != 1 {
		t.Fatalf("expected SYN sid=1 on a NEW connection, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	_ = conn2.Close()
}

// TestSessionAsConnOversizeAbandonKillsSession covers the direct-read
// design's pool gate: a payload larger than the caller's buffer leaves its
// unread tail on the TCP stream (pendRemaining); a caller that gives up
// before consuming it must not send the session back to the idle pool
// mid-frame.
func TestSessionAsConnOversizeAbandonKillsSession(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc := ts.Accept(t)
	clientHandshake(t, tc)

	payload := make([]byte, 16<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := testWriteFrame(tc, cmdPSH, 1, payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100) // far smaller than the payload: pendRemaining > 0
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close() // caller gives up; the tail is still on the stream

	conn2, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc2 := ts.Accept(t) // must be a NEW connection, not the poisoned session
	if ev := serverNextEvent(t, tc2); ev.cmd != cmdSYN || ev.sid != 1 {
		t.Fatalf("expected SYN sid=1 on a NEW connection, got cmd=%d sid=%d", ev.cmd, ev.sid)
	}
	_ = conn2.Close()
}

// TestSessionAsConnCloseWrite verifies the half-close: CloseWrite sends the
// client's cmdFIN so the server can close its upstream, reading stays open
// (the late payload and the server's FIN still arrive), and the FIN is
// idempotent across CloseWrite + Close.

// readCmdFrame reads frames from the server side, skipping control frames
// (padding/settings/alerts), and asserts the next real frame is wantCmd for
// wantSid. It auto-answers client HeartRequests like serverNextEvent does.
func readCmdFrame(t *testing.T, conn net.Conn, wantCmd byte, wantSid uint32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	_ = conn.SetReadDeadline(deadline)
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	for {
		cmd, sid, _, err := testReadFrame(conn)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if cmd == cmdHeartRequest {
			// Answer it, then let it fall through: it may BE the wanted
			// frame (Probe test).
			if err := testWriteFrame(conn, cmdHeartResponse, sid, nil); err != nil {
				t.Fatal(err)
			}
		}
		if cmd == cmdWaste || cmd == cmdSettings || cmd == cmdUpdatePaddingScheme || cmd == cmdServerSettings || cmd == cmdAlert {
			continue
		}
		if cmd != wantCmd || sid != wantSid {
			t.Fatalf("got cmd=%d sid=%d, want cmd=%d sid=%d", cmd, sid, wantCmd, wantSid)
		}
		return
	}
}

func TestSessionAsConnCloseWrite(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc := ts.Accept(t)
	serverNextEvent(t, tc)
	serverNextEvent(t, tc)

	half := conn.(interface{ CloseWrite() error })
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readCmdFrame(t, tc, cmdFIN, 1)

	// Reading stays open after the half-close: the server's late payload
	// still reaches the reader.
	if err := testWriteFrame(tc, cmdPSH, 1, []byte("late")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "late" {
		t.Fatalf("read %q, want %q", buf[:n], "late")
	}

	// CloseWrite is idempotent: a second call writes no new frame (only
	// padding-level waste may appear; another FIN would fail readCmdFrame).
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := tc.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	for {
		fcmd, fsid, _, ferr := testReadFrame(tc)
		if ferr != nil {
			break // timed out with no frame: no duplicate FIN, as wanted
		}
		if fcmd == cmdFIN {
			t.Fatalf("duplicate FIN written for sid=%d", fsid)
		}
	}
	_ = tc.SetReadDeadline(time.Time{})

	// The server finishes the response with its FIN → clean EOF.
	if err := testWriteFrame(tc, cmdFIN, 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after server FIN, got %v", err)
	}

	// Normal close returns the session to the pool; finSent suppresses the
	// duplicate FIN.
	_ = conn.Close()
	waitPool(t, d, 1)
}

// TestProbeMustNotClearReadDeadline is the production leak, distilled: a
// relay reader parks on the frame header under a deadline while the session's
// heartbeat fires mid-read. Probe must only clear the WRITE side — wiping the
// read deadline (the old behavior) disarmed the relay's idle timeout and its
// half-close ultimatum, and the reader blocked forever.
// TestSessionAsConnHalfCloseGraceDeadline pins the soft backstop: after a
// half-close the read side must terminate within halfCloseGrace on a silent
// server, instead of parking until the 60-minute relay idle timeout (the
// production leak re-created by the server's FIN-less half-close handling).
func TestSessionAsConnHalfCloseGraceDeadline(t *testing.T) {
	old := halfCloseGrace
	halfCloseGrace = 300 * time.Millisecond
	defer func() { halfCloseGrace = old }()

	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc := ts.Accept(t)
	serverNextEvent(t, tc)
	serverNextEvent(t, tc)

	half := conn.(interface{ CloseWrite() error })
	start := time.Now()
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readCmdFrame(t, tc, cmdFIN, 1)

	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the half-close grace deadline to break the silent read")
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("expected a timeout error from the grace deadline, got %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("grace deadline took %v, unbounded wait is back", elapsed)
	}

	// The conn is done; closing must be idempotent with the timer backstop.
	if err := conn.Close(); err != nil {
		t.Fatalf("Close after grace timeout: %v", err)
	}
}

// TestSessionAsConnHalfCloseActiveSurvives pins the soft backstop's
// overridden-by-liveness property: a server that keeps sending after the
// half-close keeps the relay alive past the grace window — each read re-arms
// the relay's own deadline, so an active transfer is never cut by the grace.
func TestSessionAsConnHalfCloseActiveSurvives(t *testing.T) {
	old := halfCloseGrace
	halfCloseGrace = 300 * time.Millisecond
	defer func() { halfCloseGrace = old }()

	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc := ts.Accept(t)
	serverNextEvent(t, tc)
	serverNextEvent(t, tc)

	half := conn.(interface{ CloseWrite() error })
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readCmdFrame(t, tc, cmdFIN, 1)

	// Keep the server pushing data for well past the grace window.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			if err := testWriteFrame(tc, cmdPSH, 1, []byte("chunk")); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	buf := make([]byte, 16)
	got := 0
	for got < 10 {
		// Mirror dae's relay loop: each read re-arms its own deadline,
		// which is what overrides (and thereby survives) the half-close
		// grace armed once by CloseWrite.
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("active transfer died after %d chunks: %v", got, err)
		}
		if string(buf[:n]) != "chunk" {
			t.Fatalf("read %q", buf[:n])
		}
		got++
	}
	<-done
}

func TestProbeMustNotClearReadDeadline(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc := ts.Accept(t)
	serverNextEvent(t, tc)
	serverNextEvent(t, tc)

	// Reader armed with a deadline, parked on the frame header — the
	// production shape (dae bounds every relay Read with a deadline).
	if err := conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		n   int
		err error
	}
	ch := make(chan readResult, 1)
	go func() {
		n, err := conn.Read(make([]byte, 16))
		ch <- readResult{n, err}
	}()
	time.Sleep(100 * time.Millisecond) // let the reader park first

	// Heartbeat tick mid-read. readCmdFrame auto-answers the HeartRequest
	// with HeartResponse, waking the underlying read mid-deadline just like
	// the production server does.
	prober := conn.(interface{ Probe() error })
	if err := prober.Probe(); err != nil {
		t.Fatal(err)
	}
	readCmdFrame(t, tc, cmdHeartRequest, 0)

	select {
	case res := <-ch:
		var netErr net.Error
		if !errors.As(res.err, &netErr) || !netErr.Timeout() {
			t.Fatalf("expected timeout after Probe, got %v", res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read still blocked after its deadline: Probe cleared the read deadline (the production leak)")
	}
	_ = conn.Close()
}

// TestProbeMustNotClearWriteDeadline is the write-side twin of the probe
// regression: a relay write is in flight under tcp.go's write timeout when
// the heartbeat fires. Probe may override the pending write deadline with
// its own, but it must never CLEAR one — a cleared deadline turns the
// queued writer's bounded timeout into an infinite block. After the probe
// fires, the in-flight write must therefore still terminate with a timeout
// (bounded by the probe's own 5s deadline), never hang.
func TestProbeMustNotClearWriteDeadline(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	tc := ts.Accept(t)
	serverNextEvent(t, tc)
	serverNextEvent(t, tc)

	// A relay write in flight: keep writing far past the socket buffers
	// (the server never reads) under a short write deadline, mirroring
	// dae's set-deadline-then-Write pattern.
	if err := conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	type writeResult struct {
		n   int
		err error
	}
	ch := make(chan writeResult, 1)
	go func() {
		buf := make([]byte, 64<<10)
		total, err := 0, error(nil)
		for total < 64<<20 {
			var n int
			n, err = conn.Write(buf)
			total += n
			if err != nil {
				break
			}
		}
		ch <- writeResult{total, err}
	}()
	time.Sleep(50 * time.Millisecond) // writes already flowing past the buffers

	// Heartbeat tick mid-write. The heartbeat write inherits the pending
	// deadline, so it may itself time out — which is precisely the proof
	// that the deadline survived the tick (pre-fix, Probe wiped it and
	// neither write ever failed).
	prober := conn.(interface{ Probe() error })
	if perr := prober.Probe(); perr != nil {
		var netErr net.Error
		if !errors.As(perr, &netErr) || !netErr.Timeout() {
			t.Fatalf("probe failed with non-timeout error: %v", perr)
		}
	}

	select {
	case res := <-ch:
		var netErr net.Error
		if !errors.As(res.err, &netErr) || !netErr.Timeout() {
			t.Fatalf("expected bounded write timeout after Probe, got %v", res.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Write still blocked 10s after Probe: Probe cleared the write deadline (unbounded hang)")
	}

	// Server gone, the conn is unusable either way — close cleanly.
	_ = tc.Close()
	_ = conn.Close()
}
