package anytls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"
)

// clientHandshake consumes everything the client sends after DialContext
// until its SYN and address PSH have been seen. Unlike serverNextEvent it
// also skips FIN frames: every abandoned round Close() emits one, which
// would desync a fixed two-event count.
func clientHandshake(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	synSeen := false
	for {
		cmd, sid, _, err := testReadFrame(conn)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		switch cmd {
		case cmdWaste, cmdSettings, cmdUpdatePaddingScheme, cmdServerSettings, cmdAlert, cmdFIN:
			continue
		case cmdHeartRequest:
			if err := testWriteFrame(conn, cmdHeartResponse, sid, nil); err != nil {
				t.Fatal(err)
			}
			continue
		case cmdSYN:
			synSeen = true
			continue
		case cmdPSH:
			if synSeen {
				_ = conn.SetReadDeadline(time.Time{})
				return // address PSH consumed
			}
		}
	}
}

// nextConn returns the newest TLS connection: either a brand-new one (the
// pool raced and a fresh session was dialled) or the current one (reused).
func nextConn(t *testing.T, ts *testServer, cur net.Conn) net.Conn {
	t.Helper()
	select {
	case nc := <-ts.accept:
		return nc
	case <-time.After(200 * time.Millisecond):
		return cur
	}
}

func TestStressHalfCloseResync(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	rng := rand.New(rand.NewSource(42))
	cur := nextConn(t, ts, nil) // first dial creates the session
	for round := 0; round < 60; round++ {
		if round > 0 {
			waitPool(t, d, 1) // deterministic reuse; sid keeps increasing
		}
		conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		cur = nextConn(t, ts, cur)
		clientHandshake(t, cur)

		total := 64 << 10
		data := make([]byte, total)
		rng.Read(data)
		frameSz := 16 << 10
		withNoise := round%2 == 0
		sid := uint32(round + 1)
		go func(tc net.Conn) {
			nrng := rand.New(rand.NewSource(int64(round))) // own rng: shared rand.Rand is not goroutine-safe
			off := 0
			for off < total {
				n := min(frameSz, total-off)
				if withNoise && nrng.Intn(3) == 0 {
					_ = testWriteFrame(tc, cmdWaste, 0, make([]byte, nrng.Intn(64)))
				}
				if err := testWriteFrame(tc, cmdPSH, sid, data[off:off+n]); err != nil {
					return
				}
				off += n
			}
			_ = testWriteFrame(tc, cmdFIN, sid, nil)
		}(cur)

		readTo := rng.Intn(total)
		buf := make([]byte, 32<<10)
		var got bytes.Buffer
		for got.Len() < readTo {
			n, err := conn.Read(buf)
			got.Write(buf[:n])
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				t.Fatalf("round %d read: %v (got %d/%d)", round, err, got.Len(), readTo)
			}
		}
		if !bytes.Equal(got.Bytes(), data[:got.Len()]) {
			t.Fatalf("round %d: data mismatch in first %d bytes", round, got.Len())
		}
		_ = conn.Close()
		time.Sleep(time.Duration(rng.Intn(20)) * time.Millisecond)
	}
}

func TestStressSequentialValidation(t *testing.T) {
	ts := newTestServer(t)
	d := newSessionAsConnDialer(t, ts.ln.Addr().String())
	ctx := context.Background()

	cur := nextConn(t, ts, nil)
	for round := 0; round < 40; round++ {
		if round > 0 {
			waitPool(t, d, 1)
		}
		conn, err := d.DialContext(ctx, "tcp", "t.example.com:80")
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		select {
		case nc := <-ts.accept:
			cur = nc
		case <-time.After(200 * time.Millisecond):
		}
		clientHandshake(t, cur)

		total := (8 + round%40) << 10
		data := make([]byte, total)
		for i := range data {
			data[i] = byte(round*7 + i%251)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)

			off := 0
			for off < total {
				n := min(16<<10, total-off)
				if err := testWriteFrame(cur, cmdPSH, uint32(round+1), data[off:off+n]); err != nil {
					return
				}
				off += n
			}
			_ = testWriteFrame(cur, cmdFIN, uint32(round+1), nil)
		}()

		buf := make([]byte, 8<<10)
		var got bytes.Buffer
		for {
			n, err := conn.Read(buf)
			got.Write(buf[:n])
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("round %d read: %v", round, err)
			}
		}
		if !bytes.Equal(got.Bytes(), data) {
			t.Fatalf("round %d: payload mismatch (got %d want %d)", round, got.Len(), total)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("round %d: responder stalled", round)
		}
		_ = conn.Close()
	}
}
