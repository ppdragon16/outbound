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
		// Short deadline: pendBuf bytes come back instantly (copies don't
		// consult the deadline); waiting on the next frame header times out.
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
