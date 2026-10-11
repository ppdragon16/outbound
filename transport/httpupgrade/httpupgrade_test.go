package httpupgrade

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync/atomic"
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

// upgradeRecordDialer dials the scripted peer and records the size of every
// write the TLS layer issues over it.
type upgradeRecordDialer struct {
	maxWrite atomic.Int64
	conn     net.Conn
}

func (d *upgradeRecordDialer) Alive() bool       { return true }
func (d *upgradeRecordDialer) Connect() error    { return nil }
func (d *upgradeRecordDialer) Disconnect() error { return nil }
func (d *upgradeRecordDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}
func (d *upgradeRecordDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return &upgradeRecordConn{Conn: d.conn, rec: d}, nil
}

type upgradeRecordConn struct {
	net.Conn
	rec *upgradeRecordDialer
}

func (c *upgradeRecordConn) Write(p []byte) (int, error) {
	if n := int64(len(p)); n > c.rec.maxWrite.Load() {
		c.rec.maxWrite.Store(n)
	}
	return c.Conn.Write(p)
}

// maxUpgradeTLSWriteBound is one TLS record with slack, the same bound the
// tunnel transport pins: 16KB payload + header + AEAD tag and content type.
const maxUpgradeTLSWriteBound = 16384 + 5 + 64

// TestUpgradedConnKeepsOneRecordPerWrite pins the camouflage contract of the
// upgraded relay: the uTLS conn must wrap the underlay directly, so each record
// leaves as its own write. A record coalescer folded bursts into giant writes,
// a pattern no browser produces, and production filters blackholed exactly
// those flows (2026-10) while small ones passed.
func TestUpgradedConnKeepsOneRecordPerWrite(t *testing.T) {
	cert := upgradeSelfSignedCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		srv := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := srv.Handshake(); err != nil {
			_ = srv.Close()
			return
		}
		br := bufio.NewReader(srv)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				_ = srv.Close()
				return
			}
			if line == "\r\n" {
				break
			}
		}
		if _, err := srv.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n")); err != nil {
			_ = srv.Close()
			return
		}
		// Drain until the client closes so its writes all land.
		buf := make([]byte, 32*1024)
		for {
			_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := srv.Read(buf); err != nil {
				_ = srv.Close()
				return
			}
		}
	}()

	clientEnd, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	rec := &upgradeRecordDialer{conn: clientEnd}

	d, err := NewDialer("https://example.com/up?path=/up&allowInsecure=true", rec)
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()

	burst := make([]byte, 128*1024)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	total := 0
	for total < 512*1024 {
		n, err := conn.Write(burst)
		total += n
		if err != nil {
			t.Fatalf("bulk write failed at %d bytes: %v", total, err)
		}
	}
	if got := rec.maxWrite.Load(); got > maxUpgradeTLSWriteBound {
		t.Fatalf("underlying write reached %d bytes (> %d): records were accumulated across writes - "+
			"the one-record-per-write camouflage contract is violated", got, maxUpgradeTLSWriteBound)
	}
}

func upgradeSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
		Subject:               pkix.Name{CommonName: "example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
