package server_test

// Interop tests: the real outbound masque client (protocol/masque) against
// this server package, in process. These pin the wire behavior the server
// must honor - TCP half-close, UDP datagram framing, and the zero_rtt path
// including datagrams - and double as the deployment smoke test for
// cmd/masque-server.

import (
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
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/daeuniverse/quic-go"
	utls "github.com/refraction-networking/utls"

	masque "github.com/daeuniverse/outbound/protocol/masque"
	"github.com/daeuniverse/outbound/protocol/masque/server"
)

// startProxy starts the reference server on loopback and returns its address.
// conns receives every accepted QUIC connection, so tests can read server-side
// state (e.g. Used0RTT) after traffic has flowed.
func startProxy(t *testing.T, conns func(quic.Connection)) string {
	t.Helper()
	srv, err := server.New(server.Config{
		Certificate: cert(t),
		AllowTarget: func(string, netip.AddrPort) error { return nil },
		ConnContext: func(ctx context.Context, c quic.Connection) context.Context {
			if conns != nil {
				conns(c)
			}
			return ctx
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close() })
	return pc.LocalAddr().String()
}

// startProxyWithGate is startProxy with a target gate, for the rejection paths.
func startProxyWithGate(t *testing.T, allow func(network string, addr netip.AddrPort) error) string {
	t.Helper()
	srv, err := server.New(server.Config{
		Certificate: cert(t),
		AllowTarget: allow,
	})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close() })
	return pc.LocalAddr().String()
}

// TestTCPTargetDeniedIsDelivered pins the rejection path: a denied target must
// reach the client as a 403. Hijacking the stream before validating would
// commit a default 200 (http3's HTTPStream flushes), turning the refusal into a
// successful CONNECT.
func TestTCPTargetDeniedIsDelivered(t *testing.T) {
	denied := errors.New("denied")
	proxy := startProxyWithGate(t, func(string, netip.AddrPort) error { return denied })
	c := newClient(t, proxy)

	// The client dials optimistically, so the status reaches it on first use.
	conn, err := c.DialContext(context.Background(), "tcp", "127.0.0.1:19099")
	if err == nil {
		_, err = conn.Read(make([]byte, 1))
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("dial succeeded against a target the server refuses")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want a 403 CONNECT rejection", err)
	}
}

// TestTCPUpstreamFailureIsDelivered covers the other pre-hijack failure: the
// target is allowed but unreachable, so the client must see a 502.
func TestTCPUpstreamFailureIsDelivered(t *testing.T) {
	// Nothing listens on this port.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := dead.Addr().String()
	dead.Close()

	proxy := startProxy(t, nil)
	c := newClient(t, proxy)
	conn, err := c.DialContext(context.Background(), "tcp", target)
	if err == nil {
		_, err = conn.Read(make([]byte, 1))
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("dial succeeded against an unreachable target")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("err = %v, want a 502 CONNECT rejection", err)
	}
}

// TestUDPTargetDeniedIsDelivered is the CONNECT-UDP counterpart.
func TestUDPTargetDeniedIsDelivered(t *testing.T) {
	denied := errors.New("denied")
	proxy := startProxyWithGate(t, func(string, netip.AddrPort) error { return denied })
	target := startUDPEcho(t)
	c := newClient(t, proxy)

	pc, err := c.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, err = pc.WriteTo([]byte("denied"), target)
	if err == nil {
		t.Fatal("CONNECT-UDP succeeded against a target the server refuses")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want a 403 CONNECT-UDP rejection", err)
	}
}

func cert(t *testing.T) utls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "masque-server-test"},
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

// startTCPEcho starts a TCP echo that honors half-close: after reading EOF it
// closes its write side, so a client that CloseWrites still drains the echo.
func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 2048)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						if tc, ok := c.(*net.TCPConn); ok {
							_ = tc.CloseWrite()
						}
						_, _ = io.Copy(io.Discard, c)
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startUDPEcho starts a UDP echo server.
func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, raddr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteToUDP(buf[:n], raddr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func newClient(t *testing.T, addr string, opts ...masque.Option) *masque.Client {
	t.Helper()
	c, err := masque.NewClient(addr, "masque.test", true, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestTCPTunnelHalfClose drives the plain CONNECT path and pins the half-close
// contract the relay (and our own tcpConn.CloseWrite) depends on.
func TestTCPTunnelHalfClose(t *testing.T) {
	proxy := startProxy(t, nil)
	target := startTCPEcho(t)
	c := newClient(t, proxy)

	conn, err := c.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("halfclose")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if string(got) != "halfclose" {
		t.Fatalf("echoed %q", got)
	}
}

// TestUDPTunnelDatagrams drives the CONNECT-UDP path end to end.
func TestUDPTunnelDatagrams(t *testing.T) {
	proxy := startProxy(t, nil)
	target := startUDPEcho(t)
	c := newClient(t, proxy)

	pc, err := c.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("datagram-ping"), target); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 128)
	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, raddr, err := pc.ReadFrom(got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got[:n]) != "datagram-ping" {
		t.Fatalf("echoed %q", got[:n])
	}
	if raddr.String() != target.String() {
		t.Fatalf("raddr %v, want %v", raddr, target)
	}
}

// TestDNSShapedQueriesWithDeadlines reproduces dae's DNS usage shape: every
// query dials a fresh packet conn, writes the query under a write deadline and
// reads the response under a read deadline - several times in a row on the
// same connection.
func TestDNSShapedQueriesWithDeadlines(t *testing.T) {
	proxy := startProxy(t, nil)
	target := startUDPEcho(t)
	c := newClient(t, proxy)

	for i := 0; i < 5; i++ {
		pc, err := c.ListenPacket(context.Background())
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		payload := fmt.Sprintf("dns-query-%d", i)
		if err := pc.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := pc.WriteTo([]byte(payload), target); err != nil {
			t.Fatalf("query %d write: %v", i, err)
		}
		if err := pc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 128)
		n, raddr, err := pc.ReadFrom(got)
		if err != nil {
			t.Fatalf("query %d read: %v", i, err)
		}
		if string(got[:n]) != payload {
			t.Fatalf("query %d: echoed %q, want %q", i, got[:n], payload)
		}
		if raddr.String() != target.String() {
			t.Fatalf("query %d: raddr %v", i, raddr)
		}
		_ = pc.Close()
	}
}

// TestIdleUDPRelayReleasesStreamSlots pins the relay teardown contract: when a
// UDP relay goes idle and is dropped, its stream must be closed so the
// client's slot in MaxIncomingStreams is returned. A relay that exits without
// closing the stream holds the slot until the whole QUIC connection dies, so
// a long-lived client runs out of streams and every later dial times out.
func TestIdleUDPRelayReleasesStreamSlots(t *testing.T) {
	srv, err := server.New(server.Config{
		Certificate:        cert(t),
		AllowTarget:        func(string, netip.AddrPort) error { return nil },
		IdleTimeout:        300 * time.Millisecond,
		MaxIncomingStreams: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close() })

	target := startUDPEcho(t)
	c := newClient(t, pc.LocalAddr().String())

	// Hold MaxIncomingStreams flows open without closing them.
	held := make([]net.PacketConn, 4)
	for i := range held {
		p, err := c.ListenPacket(context.Background())
		if err != nil {
			t.Fatalf("flow %d: %v", i, err)
		}
		if _, err := p.WriteTo([]byte("hold"), target); err != nil {
			t.Fatalf("flow %d write: %v", i, err)
		}
		held[i] = p
	}

	// Let the relays go idle and get dropped.
	time.Sleep(time.Second)

	// A new flow must still be possible: the dropped relays returned their
	// stream slots.
	p, err := c.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.WriteTo([]byte("after-idle"), target); err != nil {
		t.Fatalf("write after the idle relays were dropped: %v", err)
	}
}

// TestZeroRTTTunnelIncludingDatagrams is the deployment-shaped proof of the
// zero_rtt option: a resumed session's CONNECT rides in early data (server
// sees Used0RTT), and datagrams keep flowing on that same connection.
func TestZeroRTTTunnelIncludingDatagrams(t *testing.T) {
	var mu sync.Mutex
	var conns []quic.Connection
	proxy := startProxy(t, func(c quic.Connection) {
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
	})
	target := startUDPEcho(t)
	targetTCP := startTCPEcho(t)
	const sni = "zerortt-server.masque.test"

	seed := newClient(t, proxy, masque.WithZeroRTT())
	if _, err := seed.DialContext(context.Background(), "tcp", targetTCP); err != nil {
		t.Fatalf("seed dial: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // let the session ticket arrive

	// Fresh client = fresh H3 connection, resumed from the ticket.
	c := newClient(t, proxy, masque.WithZeroRTT())
	pc, err := c.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("zerortt-datagram"), target); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 128)
	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pc.ReadFrom(got); err != nil {
		t.Fatalf("read: %v", err)
	}

	if len(conns) != 2 {
		t.Fatalf("server saw %d connections, want 2", len(conns))
	}
	first := conns[0].ConnectionState().Used0RTT
	second := conns[1].ConnectionState().Used0RTT
	if first {
		t.Error("first connection has no ticket yet, must not use 0-RTT")
	}
	if !second {
		t.Error("resumed connection must send its requests as 0-RTT early data")
	}
}
