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

	quic "github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	utls "github.com/refraction-networking/utls"
)

// zrtConnKey carries the QUIC connection into the CONNECT handler so the test
// can read the server-side 0-RTT flag for each request.
type zrtConnKey struct{}

// zrtProxy is an HTTP/3 CONNECT echo proxy that records per request whether the
// client resumed its session with 0-RTT early data.
type zrtProxy struct {
	addr string

	mu   sync.Mutex
	used []bool
}

// startZRTProxy starts the proxy. allow0RTT, when non-nil, overrides the
// http3.Server default (which is to accept 0-RTT).
func startZRTProxy(t *testing.T, allow0RTT *bool) *zrtProxy {
	t.Helper()
	p := &zrtProxy{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if conn, ok := r.Context().Value(zrtConnKey{}).(quic.Connection); ok {
			p.mu.Lock()
			p.used = append(p.used, conn.ConnectionState().Used0RTT)
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
		TLSConfig: &utls.Config{Certificates: []utls.Certificate{zrtCert(t)}},
		ConnContext: func(ctx context.Context, c quic.Connection) context.Context {
			return context.WithValue(ctx, zrtConnKey{}, c)
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

func (p *zrtProxy) observed() []bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]bool(nil), p.used...)
}

// dialEcho opens one CONNECT tunnel through c and round-trips a payload.
func dialEcho(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", "echo.example.com:7")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	const payload = "zerortt-roundtrip"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}
}

// waitTicket gives the client a moment to cache the session ticket the proxy
// sends as a post-handshake message.
func waitTicket() { time.Sleep(200 * time.Millisecond) }

// TestZeroRTTConnectRidesEarlyData proves the point of the option: a resumed
// session sends the CONNECT request as 0-RTT early data, which the proxy sees
// as Used0RTT. Both control cases (no cached ticket, no WithZeroRTT) must not
// use early data.
func TestZeroRTTConnectRidesEarlyData(t *testing.T) {
	proxy := startZRTProxy(t, nil) // http3.Server accepts 0-RTT by default
	const sni = "zerortt-happy.masque.test"

	seed, err := NewClient(proxy.addr, sni, true, WithZeroRTT())
	if err != nil {
		t.Fatal(err)
	}
	dialEcho(t, seed)
	waitTicket()
	_ = seed.Close()

	resumed, err := NewClient(proxy.addr, sni, true, WithZeroRTT())
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	dialEcho(t, resumed)

	// Same ticket is available, but without the option the client must not
	// install the cache and must not attempt early data.
	plain, err := NewClient(proxy.addr, sni, true)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	dialEcho(t, plain)

	got := proxy.observed()
	if len(got) != 3 {
		t.Fatalf("proxy saw %d CONNECT requests, want 3 (%v)", len(got), got)
	}
	if got[0] {
		t.Error("first connection has no ticket yet, must not use 0-RTT")
	}
	if !got[1] {
		t.Error("resumed connection must send the CONNECT as 0-RTT early data")
	}
	if got[2] {
		t.Error("client without WithZeroRTT must not use early data")
	}
}

// TestZeroRTTRejectedRetriesWithoutEarlyData covers a proxy that takes the
// ticket but refuses the early data: the request must still succeed, on a fresh
// connection without early data, and 0-RTT must not be attempted again.
func TestZeroRTTRejectedRetriesWithoutEarlyData(t *testing.T) {
	permissive := startZRTProxy(t, nil)
	rejecting := startZRTProxy(t, boolPtr(false))
	const sni = "zerortt-retry.masque.test"

	seed, err := NewClient(permissive.addr, sni, true, WithZeroRTT())
	if err != nil {
		t.Fatal(err)
	}
	dialEcho(t, seed)
	waitTicket()
	_ = seed.Close()

	c, err := NewClient(rejecting.addr, sni, true, WithZeroRTT())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dialEcho(t, c)

	c.mu.Lock()
	zeroRTT := c.zeroRTT
	c.mu.Unlock()
	if zeroRTT {
		t.Error("client must stop attempting 0-RTT after the proxy rejected it")
	}
	for i, used := range rejecting.observed() {
		if used {
			t.Errorf("request %d on the rejecting proxy used 0-RTT", i)
		}
	}
	if len(rejecting.observed()) == 0 {
		t.Error("rejecting proxy never saw the retried request")
	}
}

func boolPtr(b bool) *bool { return &b }

func zrtCert(t *testing.T) utls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "masque-zerortt"},
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
