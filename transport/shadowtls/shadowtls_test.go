package shadowtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"hash"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// selfSignedCert returns a TLS certificate for the camouflage server.
func selfSignedCert(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startCamoServer runs a real TLS 1.3 camouflage server.
func startCamoServer(t *testing.T, host string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t, host)},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			// Drain until the (utls) client goes away.
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startV3Server runs a minimal ShadowTLS v3 server: it authenticates the
// ClientHello HMAC, relays the camouflage TLS handshake, then serves an echo
// data plane on the authenticated stream.
func startV3Server(t *testing.T, camoAddr string, users []User, firstPayload []byte) string {
	return startV3ServerDebug(t, camoAddr, users, firstPayload, nil)
}

func startV3ServerDebug(t *testing.T, camoAddr string, users []User, firstPayload []byte, fail func(string)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveV3(c, camoAddr, users, firstPayload, fail)
		}
	}()
	return ln.Addr().String()
}

func serveV3(client net.Conn, camoAddr string, users []User, firstPayload []byte, fail func(string)) {
	bail := func(reason string) {
		if fail != nil {
			fail(reason)
		}
		client.Close()
	}
	_ = bail
	defer client.Close()
	// 1. first client frame must be the authenticated ClientHello
	helloFrame, err := readFrame(client)
	if err != nil {
		bail("read CH: " + err.Error())
		return
	}
	if _, err := verifyClientHello(helloFrame, users); err != nil {
		bail("verify CH: " + err.Error())
		return
	}
	// 2. relay it to the camouflage server over a raw connection
	camo, err := net.Dial("tcp", camoAddr)
	if err != nil {
		bail("dial camo: " + err.Error())
		return
	}
	defer camo.Close()
	if err := writeBuffers(camo, helloFrame); err != nil {
		bail("write CH to camo: " + err.Error())
		return
	}
	// 3. relay ServerHello raw and capture serverRandom
	shFrame, err := readFrame(camo)
	if err != nil {
		bail("read SH from camo: " + err.Error())
		return
	}
	serverRandom := extractServerRandom(shFrame)
	if serverRandom == nil {
		bail("no serverRandom in SH")
		return
	}
	if err := writeBuffers(client, shFrame); err != nil {
		bail("write SH to client: " + err.Error())
		return
	}
	// 4. camo -> client with xor+hmac modification (handshake chain: bare
	// serverRandom seed, no side byte — matches the client's streamWrapper)
	hmacS := hmacNewPassword(users)
	hmacS.Write(serverRandom)
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		_ = copyByFrameWithModification(camo, client, users[0].Password, serverRandom, hmacS)
	}()
	// 5. client -> camo raw until the first authenticated data frame ("C" chain)
	hmacC := hmacNewPassword(users)
	hmacReset(hmacC, serverRandom, 'C')
	resetC := func() { hmacReset(hmacC, serverRandom, 'C') }
	first, err := copyByFrameUntilHMACMatches(client, camo, hmacC, resetC)
	if err != nil {
		bail("auth match: " + err.Error())
		return
	}
	// 6. authenticated: kill the camo relay and echo on the data plane with a
	// fresh "S" chain (mirrors a real backend relay taking over).
	camo.Close()
	<-relayDone
	hmacS2 := hmacNewPassword(users)
	hmacReset(hmacS2, serverRandom, 'S')
	writeS := func(payload []byte) bool {
		var header [tlsHMACHeaderSize]byte
		header[0] = applicationData
		header[1] = 3
		header[2] = 3
		binary.BigEndian.PutUint16(header[3:tlsHeaderSize], uint16(hmacSize+len(payload)))
		_, _ = hmacS2.Write(payload)
		hmacHash := hmacS2.Sum(nil)[:hmacSize]
		_, _ = hmacS2.Write(hmacHash)
		copy(header[tlsHeaderSize:], hmacHash)
		return writeBuffers(client, header[:], payload) == nil
	}
	if !writeS(first) || !writeS(firstPayload) {
		bail("write echo frames")
		return
	}
	for {
		frame, err := readFrame(client)
		if err != nil {
			return
		}
		if !verifyApplicationData(frame, hmacC, true) {
			return
		}
		if !writeS(frame[tlsHMACHeaderSize:]) {
			return
		}
	}
}

func hmacNewPassword(users []User) hash.Hash {
	return hmac.New(sha1.New, []byte(users[0].Password))
}

// readFull reads exactly len(b) bytes from the verified stream.
func readFull(t *testing.T, conn net.Conn, b []byte) {
	t.Helper()
	n := 0
	for n < len(b) {
		nn, err := conn.Read(b[n:])
		if err != nil {
			t.Fatalf("read at %d/%d: %v", n, len(b), err)
		}
		n += nn
	}
}

func TestNewConnValidation(t *testing.T) {
	if _, err := NewConn(context.Background(), nil, Config{Version: 2, Password: "x"}); err == nil {
		t.Fatal("version 2 must be rejected")
	}
	if _, err := NewConn(context.Background(), nil, Config{Version: 3, Password: ""}); err == nil {
		t.Fatal("empty password must be rejected")
	}
}

func TestV3RoundTrip(t *testing.T) {
	const host = "example.com"
	camoAddr := startCamoServer(t, host)
	users := []User{{Name: "u", Password: "p4ssw0rd"}}
	firstPayload := bytes.Repeat([]byte{'F'}, 100)
	var reasons []string
	var mu sync.Mutex
	addr := startV3ServerDebug(t, camoAddr, users, firstPayload, func(r string) {
		mu.Lock()
		reasons = append(reasons, r)
		mu.Unlock()
	})

	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := dialer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := NewConn(ctx, conn, Config{
		Password:      "p4ssw0rd",
		Version:       3,
		Sni:           host,
		Fingerprint:   "chrome",
		AllowInsecure: true,
	})
	if err != nil {
		mu.Lock()
		t.Fatalf("shadow-tls handshake: %v; server reasons: %q", err, reasons)
	}

	// The echo data plane only starts once the server has authenticated the
	// client's first record, so write before reading: the server replays the
	// matched first record (payloadA[:16384]), then its own firstPayload,
	// then echoes every verified record in order.
	payloadA := make([]byte, 40000)
	crand.Read(payloadA)
	if _, err := stream.Write(payloadA); err != nil {
		t.Fatalf("write: %v", err)
	}

	first := make([]byte, maxTLSPlaintext)
	readFull(t, stream, first)
	if !bytes.Equal(first, payloadA[:maxTLSPlaintext]) {
		t.Fatal("matched first record replay mismatch")
	}

	got := make([]byte, len(firstPayload))
	readFull(t, stream, got)
	if !bytes.Equal(got, firstPayload) {
		t.Fatal("first payload mismatch")
	}

	got = make([]byte, len(payloadA)-maxTLSPlaintext)
	readFull(t, stream, got)
	if !bytes.Equal(got, payloadA[maxTLSPlaintext:]) {
		t.Fatal("echoed payload mismatch")
	}
	stream.Close()
}

func TestV3WrongPassword(t *testing.T) {
	const host = "example.com"
	camoAddr := startCamoServer(t, host)
	users := []User{{Name: "u", Password: "right"}}
	addr := startV3Server(t, camoAddr, users, []byte("nope"))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewConn(ctx, conn, Config{
		Password:      "wrong",
		Version:       3,
		Sni:           host,
		Fingerprint:   "chrome",
		AllowInsecure: true,
	})
	if err == nil {
		t.Fatal("wrong password handshake must fail")
	}
	conn.Close()
}
