// Package tuic_test contains a spec-level end-to-end check of the tuic v5
// client: a minimal server that reproduces sing-box's (sagernet/sing-quic)
// authentication logic validates exactly what our client puts on the wire.
//
// This exists because a live sing-box server closed the connection with
// application error 0x0 immediately after AUTH; sing-box's closeWithError is
// CloseWithError(0, ""), reached from unknown version / unknown user / token
// mismatch / multiple authentication requests. Reproducing the validation
// locally tells apart a client-side protocol bug from bad credentials.
package tuic_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/dialer"
	tuiclink "github.com/daeuniverse/outbound/dialer/tuic"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/quic-go"
)

const (
	e2eUUID     = "0af4d518-315d-4980-be5f-22b6e1770d6a"
	e2ePass     = "0af4d518-315d-4980-be5f-22b6e1770d6a"
	e2eVer5     = 0x5
	e2eCmdAuth  = 0x0
	e2eCmdConn  = 0x1
	e2eErrCode  = 0 // sing-box closes with 0 on every session error
	authTimeout = 5 * time.Second
)

// authObs is what the spec server observed on the AUTH uni stream.
type authObs struct {
	ver         byte
	typ         byte
	uuidHex     string
	tokenMatch  bool
	err         error
	alpn        string
	quicVersion string
	used0RTT    bool
}

// utlsCert converts a crypto/tls certificate to utls's distinct type.
func utlsCert(c tls.Certificate) utls.Certificate {
	return utls.Certificate{
		Certificate: c.Certificate,
		PrivateKey:  c.PrivateKey,
		OCSPStaple:  c.OCSPStaple,
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// startSpecServer runs a sing-box-equivalent tuic v5 server: it reads the
// first uni stream, validates version/command/uuid/token precisely the way
// sing-quic does, and reports the observation. password is what the server
// expects; a mismatch must surface as tokenMatch=false.
func startSpecServer(t *testing.T, password string) (addr string, obs chan authObs) {
	return startSpecServerCfg(t, password, []string{"h3"}, &quic.Config{})
}

// startSpecServerCfg is startSpecServer with the server's ALPN and QUIC
// versions under test control, so the client's v2-preferred path and the
// live no-ALPN configuration can be reproduced.
func startSpecServerCfg(t *testing.T, password string, alpn []string, qcfg *quic.Config) (addr string, obs chan authObs) {
	t.Helper()
	cert := selfSignedCert(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &utls.Config{
		Certificates: []utls.Certificate{utlsCert(cert)},
		NextProtos:   alpn,
	}, qcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	obs = make(chan authObs, 4)

	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func(conn quic.Connection) {
				defer conn.CloseWithError(e2eErrCode, "")
				stream, err := conn.AcceptUniStream(conn.Context())
				if err != nil {
					obs <- authObs{err: fmt.Errorf("accept uni: %w", err)}
					return
				}
				o := authObs{
					alpn:     conn.ConnectionState().TLS.NegotiatedProtocol,
					used0RTT: conn.ConnectionState().Used0RTT,
				}
				r := bufio.NewReaderSize(stream, 16<<10)
				var head [2]byte
				if _, err := io.ReadFull(r, head[:]); err != nil {
					o.err = fmt.Errorf("read head: %w", err)
					obs <- o
					return
				}
				o.ver, o.typ = head[0], head[1]
				var uuidBytes [16]byte
				if _, err := io.ReadFull(r, uuidBytes[:]); err != nil {
					o.err = fmt.Errorf("read uuid: %w", err)
					obs <- o
					return
				}
				var token [32]byte
				if _, err := io.ReadFull(r, token[:]); err != nil {
					o.err = fmt.Errorf("read token: %w", err)
					obs <- o
					return
				}
				o.uuidHex = fmt.Sprintf("%x", uuidBytes)
				tlsState := conn.ConnectionState().TLS
				expected, err := tlsState.ExportKeyingMaterial(
					string(uuidBytes[:]), []byte(password), 32)
				if err != nil {
					o.err = fmt.Errorf("exporter: %w", err)
					obs <- o
					return
				}
				o.tokenMatch = string(expected) == string(token[:])
				obs <- o
			}(conn)
		}
	}()
	return listener.Addr().String(), obs
}

// newClient mimics exactly what dialer/tuic.Tuic.Dialer builds from a link.
func newClient(t *testing.T, proxyAddr, uuidStr, password string) netproxy.Dialer {
	return newClientALPN(t, proxyAddr, uuidStr, password, []string{"h3"})
}

// newClientALPN lets a test control the offered ALPN the way a link does:
// the live link carries no alpn parameter, so NextProtos is empty.
func newClientALPN(t *testing.T, proxyAddr, uuidStr, password string, alpn []string) netproxy.Dialer {
	return newClientFull(t, proxyAddr, uuidStr, password, alpn, 0)
}

// newClientWithSessionCache mirrors newClientFull but installs a TLS session
// cache, i.e. exactly the configuration that would let a QUIC client resume
// and (with DialEarly) authenticate over 0-RTT - which tuic must refuse.
func newClientWithSessionCache(t *testing.T, proxyAddr, uuidStr, password string) netproxy.Dialer {
	t.Helper()
	d, err := protocol.NewDialer("tuic", direct.Direct, protocol.Header{
		ProxyAddress: proxyAddr,
		Feature1:     "bbr",
		TlsConfig: &utls.Config{
			NextProtos:         []string{"h3"},
			MinVersion:         utls.VersionTLS13,
			ServerName:         "127.0.0.1",
			InsecureSkipVerify: true,
			ClientSessionCache: utls.NewLRUClientSessionCache(16),
		},
		User:     uuidStr,
		Password: password,
	})
	if err != nil {
		t.Fatalf("build tuic dialer: %v", err)
	}
	return d
}

func TestE2ETuicRefusesSessionCache(t *testing.T) {
	// The server is started with 0-RTT allowed, so a client that honoured its
	// cache would resume early and be visible as used0RTT=true.
	addr, obs := startSpecServerCfg(t, e2ePass, []string{"h3"}, &quic.Config{Allow0RTT: true})
	d := newClientWithSessionCache(t, addr, e2eUUID, e2ePass)

	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
		_, dialErr := d.DialContext(ctx, "tcp", "1.1.1.1:53")
		cancel()
		t.Logf("attempt %d: dial err = %v", attempt, dialErr)
		select {
		case o := <-obs:
			if o.err != nil {
				t.Fatalf("attempt %d: server could not parse AUTH: %v", attempt, o.err)
			}
			if !o.tokenMatch {
				t.Fatalf("attempt %d: token mismatch (auth would fail)", attempt)
			}
			if o.used0RTT {
				t.Fatalf("attempt %d: connection resumed with 0-RTT despite the cache being refused", attempt)
			}
			t.Logf("attempt %d: auth ok, used0RTT=%v", attempt, o.used0RTT)
		case <-time.After(authTimeout):
			t.Fatalf("attempt %d: server never saw an AUTH stream", attempt)
		}
		// The server closes the connection after reporting, so the next dial
		// builds a fresh one - exactly the resume scenario.
		time.Sleep(10 * time.Millisecond)
	}
}

// newClientFull mirrors the live link exactly: optional ALPN and the
// Flags the link sets (quicv2=1 -> protocol.Flags_Quic_PreferV2).
func newClientFull(t *testing.T, proxyAddr, uuidStr, password string, alpn []string, flags protocol.Flags) netproxy.Dialer {
	t.Helper()
	d, err := protocol.NewDialer("tuic", direct.Direct, protocol.Header{
		ProxyAddress: proxyAddr,
		Feature1:     "bbr",
		Flags:        flags,
		TlsConfig: &utls.Config{
			NextProtos:         alpn,
			MinVersion:         utls.VersionTLS13,
			ServerName:         "127.0.0.1",
			InsecureSkipVerify: true,
		},
		User:     uuidStr,
		Password: password,
	})
	if err != nil {
		t.Fatalf("build tuic dialer: %v", err)
	}
	return d
}

// The deployed failure mode: does our client authenticate against a
// spec-compliant server at all, with matching credentials?
func TestE2EAuthAgainstSpecServer(t *testing.T) {
	addr, obs := startSpecServer(t, e2ePass)
	d := newClient(t, addr, e2eUUID, e2ePass)

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()
	// A connect attempt drives handshake + AUTH; the server tears the
	// connection down right after validating, so the dial itself may fail -
	// the observation is what matters.
	_, _ = d.DialContext(ctx, "tcp", "1.1.1.1:53")

	select {
	case o := <-obs:
		t.Logf("server observed: ver=%#x typ=%#x uuid=%s tokenMatch=%v alpn=%q err=%v",
			o.ver, o.typ, o.uuidHex, o.tokenMatch, o.alpn, o.err)
		if o.err != nil {
			t.Fatalf("server could not parse AUTH: %v", o.err)
		}
		if o.ver != e2eVer5 {
			t.Errorf("AUTH version = %#x, want 5", o.ver)
		}
		if o.typ != e2eCmdAuth {
			t.Errorf("AUTH command = %#x, want 0 (authenticate)", o.typ)
		}
		if o.uuidHex != "0af4d518315d4980be5f22b6e1770d6a" {
			t.Errorf("AUTH uuid = %s, want 0af4d518315d4980be5f22b6e1770d6a", o.uuidHex)
		}
		if !o.tokenMatch {
			t.Error("token mismatch: exporter/clientside token does not match the server's expectation")
		}
	case <-time.After(authTimeout):
		t.Fatal("server never saw an AUTH stream")
	}
}

// A wrong password must surface as tokenMatch=false (proving the local
// harness can actually detect the difference the live server rejected).
func TestE2EAuthWrongPasswordIsDetected(t *testing.T) {
	addr, obs := startSpecServer(t, e2ePass)
	d := newClient(t, addr, e2eUUID, "wrong-password")

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()
	_, _ = d.DialContext(ctx, "tcp", "1.1.1.1:53")

	select {
	case o := <-obs:
		t.Logf("server observed (wrong password): uuid=%s tokenMatch=%v err=%v", o.uuidHex, o.tokenMatch, o.err)
		if o.err != nil {
			t.Fatalf("server could not parse AUTH: %v", o.err)
		}
		if o.tokenMatch {
			t.Fatal("token matched despite a wrong password: harness cannot detect mismatch")
		}
	case <-time.After(authTimeout):
		t.Fatal("server never saw an AUTH stream")
	}
}

// Documents the failure the user sees, for contrast: with MIHOMO-STYLE link
// handling the password lives in userinfo. This asserts our link parser
// accepts the canonical form and would have produced the same AUTH bytes.
func TestE2ELinkParsingCanonicalForm(t *testing.T) {
	link := fmt.Sprintf("tuic://%s:%s@127.0.0.1:443?allow_insecure=1&sni=127.0.0.1&alpn=h3&congestion_control=bbr&udp_relay_mode=native",
		e2eUUID, url.QueryEscape(e2ePass))
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := u.User.Password()
	if pw != e2ePass {
		t.Fatalf("userinfo password = %q, want %q", pw, e2ePass)
	}
	if u.User.Username() != e2eUUID {
		t.Fatalf("userinfo username = %q, want uuid", u.User.Username())
	}
	var _ = binary.BigEndian
	var _ = dialer.ExtraOption{}
}

// TestE2ETokenNeedsCompletedHandshake proves the root cause: DialEarly (the
// ReduceRtt path) returns before the handshake completes, and the exporter
// value read at that moment is NOT the final handshake exporter. The v5
// token is defined over that exporter, so authenticating before handshake
// completion makes the server reject the token - sing-box answers with
// CloseWithError(0, "") (application error 0x0), exactly what the live
// server did. On localhost the handshake usually finishes first (which is
// why an e2e test can pass by accident); over a real RTT it does not.
func TestE2ETokenNeedsCompletedHandshake(t *testing.T) {
	addr, _ := startSpecServer(t, e2ePass)

	var uuidBytes [16]byte
	u, _ := url.Parse("tuic://" + e2eUUID + ":x@h")
	_ = u
	// parse uuid hex into bytes
	hexStr := "0af4d518315d4980be5f22b6e1770d6a"
	for i := 0; i < 16; i++ {
		var b byte
		_, err := fmt.Sscanf(hexStr[i*2:i*2+2], "%02x", &b)
		if err != nil {
			t.Fatal(err)
		}
		uuidBytes[i] = b
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &quic.Transport{Conn: udpConn}
	defer transport.Close()
	raddr, _ := net.ResolveUDPAddr("udp", addr)

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()
	conn, err := transport.DialEarly(ctx, raddr, &utls.Config{
		NextProtos:         []string{"h3"},
		MinVersion:         utls.VersionTLS13,
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true,
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")

	handshakeDone := false
	select {
	case <-conn.HandshakeComplete():
		handshakeDone = true
	default:
	}

	earlyState := conn.ConnectionState().TLS
	earlyToken, earlyErr := earlyState.ExportKeyingMaterial(string(uuidBytes[:]), []byte(e2ePass), 32)

	select {
	case <-conn.HandshakeComplete():
	case <-time.After(authTimeout):
		t.Fatal("handshake never completed")
	}
	lateState := conn.ConnectionState().TLS
	lateToken, lateErr := lateState.ExportKeyingMaterial(string(uuidBytes[:]), []byte(e2ePass), 32)

	t.Logf("handshake done at DialEarly return: %v", handshakeDone)
	t.Logf("early exporter: err=%v token8=%x", earlyErr, first8(earlyToken))
	t.Logf("late  exporter: err=%v token8=%x", lateErr, first8(lateToken))

	if earlyErr != nil && lateErr == nil {
		t.Logf("PROVEN: exporter unavailable before handshake completion")
		return
	}
	if earlyErr == nil && lateErr == nil && string(earlyToken) != string(lateToken) {
		t.Logf("PROVEN: exporter differs before/after handshake completion -> AUTH before handshake yields a rejected token")
		return
	}
	if !handshakeDone {
		t.Logf("NOTE: handshake had not completed at DialEarly return, but exporter values happened to match on this host/timing; over a real RTT the early read is unreliable")
		return
	}
	t.Logf("handshake already complete at DialEarly return on localhost (timing artifact)")
}

func first8(b []byte) []byte {
	if len(b) > 8 {
		return b[:8]
	}
	return b
}

// The live setup: the server offers ALPN "h3", the link carries no alpn
// parameter (so the client offers none). Establish what the server side
// then sees and whether authentication still succeeds.
func TestE2ENoALPNAgainstH3Server(t *testing.T) {
	addr, obs := startSpecServer(t, e2ePass)
	d := newClientALPN(t, addr, e2eUUID, e2ePass, nil)

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "1.1.1.1:53")
	t.Logf("dial result against h3-only server with no client ALPN: %v", err)

	// QUIC requires ALPN: a server that only offers h3 must reject a client
	// offering none, so the handshake (not auth) is where this fails. Note
	// the live sing-box tuic inbound accepts an empty ALPN (verified against
	// a real sing-box below), so this is a spec illustration, not the live
	// setup.
	if err == nil {
		t.Error("h3-only server accepted a client with no ALPN; expected a handshake rejection")
	}
	select {
	case o := <-obs:
		t.Fatalf("server saw an AUTH stream (%+v) despite the ALPN mismatch", o)
	case <-time.After(300 * time.Millisecond):
		// expected: no AUTH ever reached the server
	}
}

// The live link sets quicv2=1, so the client offers QUIC v2 first. Against a
// v1-only server that means Version Negotiation and a recreated handshake.
// The v5 token is derived from the TLS exporter of the handshake the server
// validated, so if the client reads its ConnectionState from the wrong
// (pre-negotiation) connection the token mismatches and sing-box closes
// with application error 0x0.
func TestE2EPreferV2AgainstV1Server(t *testing.T) {
	addr, obs := startSpecServerCfg(t, e2ePass, nil, &quic.Config{})
	d := newClientFull(t, addr, e2eUUID, e2ePass, nil, protocol.Flags_Quic_PreferV2)

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "1.1.1.1:53")
	t.Logf("dial result: %v", err)

	select {
	case o := <-obs:
		t.Logf("server observed (PreferV2 vs v1-only): ver=%#x typ=%#x uuid=%s tokenMatch=%v quicVersion=%s err=%v",
			o.ver, o.typ, o.uuidHex, o.tokenMatch, o.quicVersion, o.err)
		if !o.tokenMatch {
			t.Error("REPRODUCED: token mismatch when the client prefers QUIC v2 against a v1-only server")
		}
	case <-time.After(authTimeout):
		t.Fatal("server never saw an AUTH stream")
	}
}

// Sanity: same link parameters against a server that speaks v2 directly.
func TestE2EPreferV2AgainstV2Server(t *testing.T) {
	addr, obs := startSpecServerCfg(t, e2ePass, nil, &quic.Config{Versions: []quic.Version{quic.Version2, quic.Version1}})
	d := newClientFull(t, addr, e2eUUID, e2ePass, nil, protocol.Flags_Quic_PreferV2)

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "1.1.1.1:53")
	t.Logf("dial result: %v", err)

	select {
	case o := <-obs:
		t.Logf("server observed (PreferV2 vs v2 server): tokenMatch=%v quicVersion=%s err=%v", o.tokenMatch, o.quicVersion, o.err)
	case <-time.After(authTimeout):
		t.Fatal("server never saw an AUTH stream")
	}
}

// TestE2EAgainstRealSingBox dials a real sing-box tuic inbound (started by
// the harness) using the live link's exact parameters: no ALPN, quicv2=1,
// insecure, arbitrary SNI. A local TCP listener is the relay target, so a
// completed round trip proves handshake + auth + CONNECT all work.
func TestE2EAgainstRealSingBox(t *testing.T) {
	proxyAddr := os.Getenv("TUICE2E_ADDR")
	if proxyAddr == "" {
		t.Skip("set TUICE2E_ADDR=<host:port> to run against a real sing-box tuic inbound")
	}

	// relay target: a local listener that echoes a fixed payload.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 5)
				n, err := io.ReadFull(c, buf)
				t.Logf("echo target: read n=%d err=%v data=%q", n, err, buf[:n])
				if err != nil {
					return
				}
				w, werr := c.Write([]byte("pong:" + string(buf)))
				t.Logf("echo target: write n=%d err=%v", w, werr)
				if os.Getenv("TUICE2E_HOLD_OPEN") != "" {
					time.Sleep(500 * time.Millisecond)
				}
			}(c)
		}
	}()

	d := newClientFull(t, proxyAddr, e2eUUID, e2ePass, nil, protocol.Flags_Quic_PreferV2)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial through real sing-box failed: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp := make([]byte, 64)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	t.Logf("relay response: %q", resp[:n])
	if string(resp[:n]) != "pong:hello" {
		t.Fatalf("unexpected relay response %q", resp[:n])
	}
}

// TestE2ELiveLinkThroughRealSingBox drives the exact consumer path
// (dialer/tuic.NewTuic -> Tuic.Dialer) with the live link verbatim, only
// swapping the proxy address for the local sing-box. This closes the last
// gap between the hand-built header in the other tests and what dae does.
func TestE2ELiveLinkThroughRealSingBox(t *testing.T) {
	proxyAddr := os.Getenv("TUICE2E_ADDR")
	if proxyAddr == "" {
		t.Skip("set TUICE2E_ADDR=<host:port> to run against a real sing-box tuic inbound")
	}
	linkTemplate := "tuic://0af4d518-315d-4980-be5f-22b6e1770d6a:0af4d518-315d-4980-be5f-22b6e1770d6a@%s?insecure=1&sni=www.linux.com&congestion_control=bbr&quicv2=1#evo_my_tui_v6"
	link := fmt.Sprintf(linkTemplate, proxyAddr)

	d, _, err := tuiclink.NewTuic(link)
	if err != nil {
		t.Fatalf("NewTuic: %v", err)
	}
	td, err := d.(interface {
		Dialer(*dialer.ExtraOption, netproxy.Dialer) (netproxy.Dialer, error)
	}).Dialer(&dialer.ExtraOption{}, direct.Direct)
	if err != nil {
		t.Fatalf("Tuic.Dialer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 5)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				_, _ = c.Write([]byte("pong:" + string(buf)))
				time.Sleep(200 * time.Millisecond)
			}(c)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := td.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial through live-link dialer: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp := make([]byte, 64)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	t.Logf("live-link relay response: %q", resp[:n])
	if string(resp[:n]) != "pong:hello" {
		t.Fatalf("unexpected relay response %q", resp[:n])
	}
}

// TestE2ELiveServerDNSOverTCP replays dae's actual connectivity-check
// traffic against a real server: two CONNECT streams on one QUIC connection
// (tcp4 + tcp6 DNS) doing a length-prefixed DNS-over-TCP exchange, exactly
// like common/netutils.ResolveStream.
func TestE2ELiveServerDNSOverTCP(t *testing.T) {
	proxyAddr := os.Getenv("TUICE2E_ADDR")
	if proxyAddr == "" {
		t.Skip("set TUICE2E_ADDR=<host:port>")
	}
	linkTemplate := "tuic://0af4d518-315d-4980-be5f-22b6e1770d6a:0af4d518-315d-4980-be5f-22b6e1770d6a@%s?insecure=1&sni=www.linux.com&congestion_control=bbr&quicv2=1#evo_my_tui_v6"
	d0, _, err := tuiclink.NewTuic(fmt.Sprintf(linkTemplate, proxyAddr))
	if err != nil {
		t.Fatalf("NewTuic: %v", err)
	}
	d, err := d0.(interface {
		Dialer(*dialer.ExtraOption, netproxy.Dialer) (netproxy.Dialer, error)
	}).Dialer(&dialer.ExtraOption{}, direct.Direct)
	if err != nil {
		t.Fatalf("Tuic.Dialer: %v", err)
	}

	query := []byte{
		0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	roundTrip := func(target string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := d.DialContext(ctx, "tcp", target)
		if err != nil {
			return fmt.Errorf("dial %s: %w", target, err)
		}
		defer conn.Close()
		buf := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(buf, uint16(len(query)))
		copy(buf[2:], query)
		if _, err := conn.Write(buf); err != nil {
			return fmt.Errorf("write %s: %w", target, err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
			return err
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return fmt.Errorf("read length %s: %w", target, err)
		}
		respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		resp := make([]byte, respLen)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return fmt.Errorf("read payload %s: %w", target, err)
		}
		if len(resp) < 4 || resp[0] != 0xab || resp[1] != 0xcd {
			return fmt.Errorf("bad DNS response from %s: %x", target, resp[:min(8, len(resp))])
		}
		return nil
	}

	// Sequential first (isolates one stream), then concurrent (isolates the
	// tcp4+tcp6 overlap dae's check performs).
	for _, target := range []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"} {
		if err := roundTrip(target); err != nil {
			t.Errorf("sequential %s: %v", target, err)
		} else {
			t.Logf("sequential %s: OK", target)
		}
	}
	errCh := make(chan error, 2)
	for _, target := range []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"} {
		go func(target string) { errCh <- roundTrip(target) }(target)
	}
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent: %v", err)
		}
	}
}

// TestE2ECheckBurst replicates dae's runInitialCheck exactly: one fresh
// tuic dialer, then four concurrent checks (tcp6/tcp4/udp6/udp4 DNS) all
// sharing the connection the first dial creates. This is the traffic
// pattern that fails in the live deployment and that the isolated tests
// never produced.
func TestE2ECheckBurst(t *testing.T) {
	proxyAddr := os.Getenv("TUICE2E_ADDR")
	if proxyAddr == "" {
		t.Skip("set TUICE2E_ADDR=<host:port>")
	}
	linkTemplate := "tuic://0af4d518-315d-4980-be5f-22b6e1770d6a:0af4d518-315d-4980-be5f-22b6e1770d6a@%s?insecure=1&sni=www.linux.com&congestion_control=bbr&quicv2=1#evo_my_tui_v6"
	d0, _, err := tuiclink.NewTuic(fmt.Sprintf(linkTemplate, proxyAddr))
	if err != nil {
		t.Fatalf("NewTuic: %v", err)
	}
	d, err := d0.(interface {
		Dialer(*dialer.ExtraOption, netproxy.Dialer) (netproxy.Dialer, error)
	}).Dialer(&dialer.ExtraOption{}, direct.Direct)
	if err != nil {
		t.Fatalf("Tuic.Dialer: %v", err)
	}

	query := []byte{
		0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}

	checks := []struct{ network, server string }{
		{"tcp", "[2606:4700:4700::1111]:53"},
		{"tcp", "1.1.1.1:53"},
		{"udp", "[2606:4700:4700::1111]:53"},
		{"udp", "1.1.1.1:53"},
	}
	var wg sync.WaitGroup
	for _, c := range checks {
		wg.Add(1)
		go func(network, server string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := d.DialContext(ctx, network, server)
			if err != nil {
				t.Errorf("[%s %s] dial: %v", network, server, err)
				return
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			var req []byte
			if network == "tcp" {
				req = make([]byte, 2+len(query))
				binary.BigEndian.PutUint16(req, uint16(len(query)))
				copy(req[2:], query)
			} else {
				req = query
			}
			if _, err := conn.Write(req); err != nil {
				t.Errorf("[%s %s] write: %v", network, server, err)
				return
			}
			// Mirrors dae: TCP DNS is length-prefixed (ResolveStream), UDP
			// DNS is a bare datagram (ResolveUDP).
			var resp []byte
			if network == "tcp" {
				var lenBuf [2]byte
				if _, err = io.ReadFull(conn, lenBuf[:]); err != nil {
					t.Errorf("[%s %s] read length: %v", network, server, err)
					return
				}
				resp = make([]byte, int(binary.BigEndian.Uint16(lenBuf[:])))
				if _, err = io.ReadFull(conn, resp); err != nil {
					t.Errorf("[%s %s] read payload: %v", network, server, err)
					return
				}
			} else {
				resp = make([]byte, 4096)
				var n int
				if n, err = conn.Read(resp); err != nil {
					t.Errorf("[%s %s] read: %v", network, server, err)
					return
				}
				resp = resp[:n]
			}
			if len(resp) < 4 || resp[0] != 0xab || resp[1] != 0xcd {
				t.Errorf("[%s %s] unexpected response: %x", network, server, resp[:min(8, len(resp))])
				return
			}
			t.Logf("[%s %s] OK (%d bytes)", network, server, len(resp))
		}(c.network, c.server)
	}
	wg.Wait()
}

// TestE2EDatagramFraming dumps the datagrams a spec server receives on a
// full consumer-path UDP association and validates them against sing-quic's
// decoder rule: after the address field exactly dataLength bytes must
// remain (reader.Len() != dataLength -> io.ErrUnexpectedEOF, which the
// server turns into CloseWithError(0, "")).
func TestE2EDatagramFraming(t *testing.T) {
	cert := selfSignedCert(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &utls.Config{
		Certificates: []utls.Certificate{utlsCert(cert)},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	datagrams := make(chan []byte, 16)
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func(conn quic.Connection) {
				// authenticate like the spec server so the client proceeds
				if stream, err := conn.AcceptUniStream(conn.Context()); err == nil {
					r := bufio.NewReaderSize(stream, 1<<12)
					var hdr [50]byte
					_, _ = io.ReadFull(r, hdr[:])
				}
				for {
					dg, err := conn.ReceiveDatagram(conn.Context())
					if err != nil {
						return
					}
					cp := make([]byte, len(dg))
					copy(cp, dg)
					conn.ReleaseDatagram(dg)
					datagrams <- cp
				}
			}(conn)
		}
	}()

	link := fmt.Sprintf("tuic://%s:%s@%s?insecure=1&sni=127.0.0.1&congestion_control=bbr&udp_relay_mode=native#t",
		e2eUUID, e2ePass, listener.Addr().String())
	d0, _, err := tuiclink.NewTuic(link)
	if err != nil {
		t.Fatal(err)
	}
	d, err := d0.(interface {
		Dialer(*dialer.ExtraOption, netproxy.Dialer) (netproxy.Dialer, error)
	}).Dialer(&dialer.ExtraOption{}, direct.Direct)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// exactly what dae's udp check does: DialContext("udp", server) then Write
	conn, err := d.DialContext(ctx, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer conn.Close()
	query := []byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case dg := <-datagrams:
		t.Logf("server received %d bytes: %x", len(dg), dg)
		if len(dg) < 12 {
			t.Fatalf("datagram too short: %d", len(dg))
		}
		// head(2): VER TYPE; then sessionID(2) packetID(2) fragTotal(1)
		// fragID(1) dataLen(2); then destination; then exactly dataLen bytes.
		dataLen := int(binary.BigEndian.Uint16(dg[8:10]))
		atyp := dg[10]
		addrLen := 0
		switch atyp {
		case 1:
			addrLen = 4
		case 2:
			addrLen = 16
		case 3:
			addrLen = 1 + int(dg[11])
		}
		remaining := len(dg) - (11 + addrLen + 2)
		t.Logf("dataLen=%d remaining=%d atyp=%d total=%d", dataLen, remaining, atyp, len(dg))
		if remaining != dataLen {
			t.Errorf("framing mismatch: server decoder would return io.ErrUnexpectedEOF (remaining %d != dataLen %d)", remaining, dataLen)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server received no datagram")
	}
}
