package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	quic "github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	utls "github.com/refraction-networking/utls"
)

func TestParseMasqueURL(t *testing.T) {
	d, prop, err := NewMasque("masque://proxy.example.com:443?peer=cdn.example.com&insecure=1#hk")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := d.(*Masque)
	if !ok {
		t.Fatalf("unexpected type %T", d)
	}
	if m.Host != "proxy.example.com:443" || m.Sni != "cdn.example.com" || !m.Insecure || m.Name != "hk" {
		t.Fatalf("parsed %+v", m)
	}
	if prop.Protocol != "masque" || prop.Address != "proxy.example.com:443" || prop.Name != "hk" {
		t.Fatalf("property %+v", prop)
	}

	if _, _, err := NewMasque("masque://"); err == nil {
		t.Fatal("empty host must be rejected")
	}
	if _, _, err := NewMasque("http://example.com"); err == nil {
		t.Fatal("non-masque scheme must be rejected")
	}
}

func TestParseMasqueURLQuicV2(t *testing.T) {
	const want = true
	for _, link := range []string{
		"masque://proxy.example.com:443?quic_version=2",
		"masque://proxy.example.com:443?quic-version=v2",
		"masque://proxy.example.com:443?quicv2=1",
	} {
		d, _, err := NewMasque(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		if got := d.(*Masque).QuicV2; got != want {
			t.Errorf("%s: QuicV2 = %v, want %v", link, got, want)
		}
	}
	d, _, err := NewMasque("masque://proxy.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if d.(*Masque).QuicV2 {
		t.Error("QuicV2 must default to false")
	}
}

func TestParseMasqueURLZeroRTT(t *testing.T) {
	for _, link := range []string{
		"masque://proxy.example.com:443?zero_rtt=1",
		"masque://proxy.example.com:443?zero-rtt=true",
		"masque://proxy.example.com:443?0rtt=1",
		"masque://proxy.example.com:443?reduce_rtt=1",
	} {
		d, _, err := NewMasque(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		if !d.(*Masque).ZeroRTT {
			t.Errorf("%s: ZeroRTT must be set", link)
		}
	}
	d, _, err := NewMasque("masque://proxy.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if d.(*Masque).ZeroRTT {
		t.Error("ZeroRTT must default to false")
	}
}

// TestDialerZeroRTT checks that the link flag reaches the wire: a second
// connection to the same proxy resumes the session and sends the CONNECT as
// 0-RTT early data.
func TestDialerZeroRTT(t *testing.T) {
	proxy := startEchoProxyWith(t, nil)
	const sni = "zerortt-dialer.masque.test"

	d, err := NewDialer(nil, proxy.addr, sni, true, false, true, 0, "", false)
	if err != nil {
		t.Fatal(err)
	}
	roundTripEcho(t, d)
	time.Sleep(200 * time.Millisecond) // let the session ticket arrive

	// A fresh dialer opens a fresh H3 connection; it must resume with 0-RTT.
	d2, err := NewDialer(nil, proxy.addr, sni, true, false, true, 0, "", false)
	if err != nil {
		t.Fatal(err)
	}
	roundTripEcho(t, d2)

	got := proxy.observed()
	if len(got) != 2 {
		t.Fatalf("proxy saw %d CONNECT requests, want 2 (%v)", len(got), got)
	}
	if got[0] {
		t.Error("first connection has no ticket yet, must not use 0-RTT")
	}
	if !got[1] {
		t.Error("dialer with zero_rtt must resume with 0-RTT early data")
	}
}

// roundTripEcho writes and reads one payload through a CONNECT tunnel.
func roundTripEcho(t *testing.T, d netproxy.Dialer) {
	t.Helper()
	conn, err := d.DialContext(context.Background(), "tcp", "echo.example.com:7")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("zerortt")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("zerortt"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "zerortt" {
		t.Fatalf("got %q", got)
	}
}

// TestDialerEndToEnd exercises the netproxy.Dialer surface against a real
// HTTP/3 CONNECT proxy.
func TestDialerEndToEnd(t *testing.T) {
	addr := startEchoProxy(t)
	d, err := NewDialer(nil, addr, "masque.test", true, false, false, 0, "", false)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", "echo.example.com:7")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("dialer-roundtrip")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("dialer-roundtrip"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "dialer-roundtrip" {
		t.Fatalf("got %q", got)
	}

	// the shared client is reused across dials
	conn2, err := d.DialContext(context.Background(), "tcp", "echo2.example.com:7")
	if err != nil {
		t.Fatal(err)
	}
	conn2.Close()

	// "udp" returns a bound CONNECT-UDP packet conn (lazy: no datagrams flow
	// until the first WriteTo).
	pcConn, err := d.DialContext(context.Background(), "udp", "x:1")
	if err != nil {
		t.Fatalf("udp DialContext: %v", err)
	}
	pcConn.Close()

	pc, err := d.ListenPacket(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
}

func TestDialerRequiresAddress(t *testing.T) {
	if _, err := NewDialer(nil, "", "", false, false, false, 0, "", false); err == nil {
		t.Fatal("empty address must be rejected")
	}
}

// echoProxy serves plain HTTP/3 CONNECT with an echo tunnel and records, per
// CONNECT request, whether the client resumed with 0-RTT early data.
type echoProxy struct {
	addr string

	mu       sync.Mutex
	used0RTT []bool
}

func (p *echoProxy) observed() []bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]bool(nil), p.used0RTT...)
}

// startEchoProxy serves plain HTTP/3 CONNECT with an echo tunnel.
func startEchoProxy(t *testing.T) string {
	t.Helper()
	return startEchoProxyWith(t, nil).addr
}

// startEchoProxyWith starts the echo proxy; allow0RTT, when non-nil, overrides
// the http3.Server default (which is to accept 0-RTT).
func startEchoProxyWith(t *testing.T, allow0RTT *bool) *echoProxy {
	t.Helper()
	p := &echoProxy{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if conn, ok := r.Context().Value(echoConnKey{}).(quic.Connection); ok {
			p.mu.Lock()
			p.used0RTT = append(p.used0RTT, conn.ConnectionState().Used0RTT)
			p.mu.Unlock()
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
		ConnContext: func(ctx context.Context, c quic.Connection) context.Context {
			return context.WithValue(ctx, echoConnKey{}, c)
		},
	}
	if allow0RTT != nil {
		server.QUICConfig = &quic.Config{Allow0RTT: *allow0RTT}
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	p.addr = pc.LocalAddr().String()
	go func() { _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close() })
	return p
}

// echoConnKey carries the QUIC connection into the CONNECT handler.
type echoConnKey struct{}

func selfSignedCert(t *testing.T) utls.Certificate {
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

var (
	_ netproxy.Dialer = (*Dialer)(nil)
	_ dialer.Dialer   = (*Masque)(nil)
)

func TestParseMasqueURLMTU(t *testing.T) {
	for _, tc := range []struct {
		link string
		want int
	}{
		{"masque://proxy.example.com:443?mtu=1452", 1452},
		{"masque://proxy.example.com:443?mtu=1440", 1440},
		{"masque://proxy.example.com:443", 0},
		{"masque://proxy.example.com:443?mtu=999", 0},   // below the QUIC minimum
		{"masque://proxy.example.com:443?mtu=abc", 0},   // unparsable
		{"masque://proxy.example.com:443?mtu=70000", 0}, // out of range
	} {
		d, _, err := NewMasque(tc.link)
		if err != nil {
			t.Fatalf("%s: %v", tc.link, err)
		}
		if got := d.(*Masque).MTU; got != tc.want {
			t.Errorf("%s: MTU = %d, want %d", tc.link, got, tc.want)
		}
	}
}
