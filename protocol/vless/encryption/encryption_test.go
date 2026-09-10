package encryption

import (
	"bytes"
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"crypto/mlkem"
)

// genTestKeys builds one ML-KEM-768 keypair and one X25519 keypair, and
// returns the client "encryption" string and the server "decryption" string.
// seconds is the server-side ticket validity ("0" = 1-RTT only, "30" enables
// 0-RTT); the client string always uses 1rtt/0rtt accordingly.
func genTestKeys(t *testing.T, mode string, seconds string) (clientStr, serverStr string) {
	t.Helper()
	seed := make([]byte, MLKEM768SeedLength)
	if _, err := crand.Read(seed); err != nil {
		t.Fatal(err)
	}
	dKey, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		t.Fatal(err)
	}
	clientMLKEM := dKey.EncapsulationKey().Bytes()

	xPriv := make([]byte, X25519PrivateKeySize)
	if _, err := crand.Read(xPriv); err != nil {
		t.Fatal(err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(xPriv)
	if err != nil {
		t.Fatal(err)
	}
	clientX25519 := priv.PublicKey().Bytes()

	b64 := base64.RawURLEncoding.EncodeToString
	clientRTT := "1rtt"
	if seconds != "0" {
		clientRTT = "0rtt"
	}
	clientStr = strings.Join([]string{
		"mlkem768x25519plus", mode, clientRTT, b64(clientMLKEM), b64(clientX25519),
	}, ".")
	serverStr = strings.Join([]string{
		"mlkem768x25519plus", mode, seconds, b64(seed), b64(xPriv),
	}, ".")
	return
}

// handshakePair runs a client-server handshake over TCP loopback (not
// net.Pipe: the handshake overlaps full-duplex padding writes, which
// deadlocks on net.Pipe's unbuffered semantics).
//
// The server handshake result is delivered asynchronously on serverC /
// serverEr: in the 0-RTT case the server handshake can only complete after
// the client's first CommonConn.Write (which flushes the buffered
// pre-write), so handshakePair must never block on it.
func handshakePair(t *testing.T, client *ClientInstance, server *ServerInstance) (c *CommonConn, serverC chan *CommonConn, serverEr chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acceptCh := make(chan net.Conn, 1)
	go func() {
		sc, err := ln.Accept()
		if err != nil {
			return
		}
		acceptCh <- sc
	}()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var c2 net.Conn
	select {
	case c2 = <-acceptCh:
	case <-time.After(5 * time.Second):
		t.Fatal("accept timeout")
	}
	serverC = make(chan *CommonConn, 1)
	serverEr = make(chan error, 1)
	go func() {
		sc, er := server.Handshake(c2, nil)
		serverC <- sc
		serverEr <- er
	}()
	c, err = client.Handshake(c1)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	t.Cleanup(func() {
		c1.Close()
		c2.Close()
	})
	return c, serverC, serverEr
}

// fetchServer blocks until the server handshake has completed.
func fetchServer(t *testing.T, serverC chan *CommonConn, serverEr chan error) *CommonConn {
	t.Helper()
	sc := <-serverC
	if er := <-serverEr; er != nil {
		t.Fatalf("server handshake: %v", er)
	}
	return sc
}

func writeAll(t *testing.T, a *CommonConn, payload []byte) {
	t.Helper()
	if _, err := a.Write(payload); err != nil {
		// Errorf (not Fatalf): writeAll may run on a non-test goroutine.
		t.Errorf("write side (%d bytes): %v", len(payload), err)
	}
}

func readAndVerify(t *testing.T, b *CommonConn, payload []byte) {
	t.Helper()
	got := make([]byte, len(payload))
	n := 0
	for n < len(payload) {
		nn, err := b.Read(got[n:])
		if err != nil {
			t.Fatalf("read side (%d bytes): %v", len(payload), err)
		}
		n += nn
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch at size %d", len(payload))
	}
}

func TestHandshakeRoundTrip(t *testing.T) {
	for _, mode := range []string{"native", "xorpub", "random"} {
		mode := mode
		t.Run(mode+"/1rtt", func(t *testing.T) {
			clientStr, serverStr := genTestKeys(t, mode, "0")
			client, err := NewClient(clientStr)
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewServer(serverStr)
			if err != nil {
				t.Fatal(err)
			}
			c, serverC, serverEr := handshakePair(t, client, server)
			s := fetchServer(t, serverC, serverEr)
			// client -> server, including multi-record (8192 framing) sizes
			for _, size := range []int{1, 100, 8192, 8192*2 + 17} {
				payload := make([]byte, size)
				crand.Read(payload)
				writeAll(t, c, payload)
				readAndVerify(t, s, payload)
			}
			// server -> client
			payload := make([]byte, 2048)
			crand.Read(payload)
			writeAll(t, s, payload)
			readAndVerify(t, c, payload)
		})
	}
}

func TestZeroRTTRoundTrip(t *testing.T) {
	clientStr, serverStr := genTestKeys(t, "native", "30")
	client, err := NewClient(clientStr)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(serverStr)
	if err != nil {
		t.Fatal(err)
	}
	// First handshake is 1-RTT and issues the ticket.
	c, serverC, serverEr := handshakePair(t, client, server)
	s := fetchServer(t, serverC, serverEr)
	payload := make([]byte, 333)
	crand.Read(payload)
	writeAll(t, c, payload)
	readAndVerify(t, s, payload)

	// Second handshake must take the 0-RTT path.
	if client.Ticket == nil {
		t.Fatal("client did not save a ticket after 1-RTT handshake")
	}
	c2, serverC2, serverEr2 := handshakePair(t, client, server)
	// The client's 0-RTT handshake only flushes its buffered pre-write on the
	// first CommonConn.Write, which is also what lets the server handshake
	// finish: write in a goroutine first, then fetch the server conn.
	payload2 := make([]byte, 512)
	crand.Read(payload2)
	go writeAll(t, c2, payload2)
	s2 := fetchServer(t, serverC2, serverEr2)
	readAndVerify(t, s2, payload2)
	// and back
	payload3 := make([]byte, 700)
	crand.Read(payload3)
	writeAll(t, s2, payload3)
	readAndVerify(t, c2, payload3)
}

func TestNewClientParsing(t *testing.T) {
	if c, err := NewClient(""); err != nil || c != nil {
		t.Fatalf("empty encryption should give nil client, got %v, %v", c, err)
	}
	if c, err := NewClient("none"); err != nil || c != nil {
		t.Fatalf("none encryption should give nil client, got %v, %v", c, err)
	}
	if _, err := NewClient("mlkem768x25519plus.bogus.1rtt.x"); err == nil {
		t.Fatal("bogus mode should fail")
	}
	if _, err := NewClient("mlkem768x25519plus.native.bogus.x"); err == nil {
		t.Fatal("bogus rtt should fail")
	}
	clientStr, serverStr := genTestKeys(t, "native", "0")
	if _, err := NewClient(clientStr); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(serverStr); err == nil {
		t.Fatal("server seed should not be usable as client key")
	}
	// padding spec
	padStr := clientStr + ".100-111-1111.50-0-3333"
	c, err := NewClient(padStr)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.PaddingLens) != 1 || len(c.PaddingGaps) != 1 ||
		len(c.PaddingLens[0]) != 3 || len(c.PaddingGaps[0]) != 3 {
		t.Fatalf("padding spec not parsed: %v %v", c.PaddingLens, c.PaddingGaps)
	}
}

func TestGenKeys(t *testing.T) {
	seed, client, hash32, err := GenMLKEM768("")
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 86 || len(client) != 1579 || len(hash32) != 43 { // base64 raw lengths
		t.Fatalf("unexpected base64 lengths: %d %d %d", len(seed), len(client), len(hash32))
	}
	// seed roundtrip
	seed2, client2, _, err := GenMLKEM768(seed)
	if err != nil {
		t.Fatal(err)
	}
	if seed2 != seed || client2 != client {
		t.Fatal("ML-KEM-768 seed roundtrip mismatch")
	}
	priv, pass, hash32x, err := GenX25519("")
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 43 || len(pass) != 43 || len(hash32x) != 43 {
		t.Fatalf("unexpected X25519 base64 lengths: %d %d %d", len(priv), len(pass), len(hash32x))
	}
}
