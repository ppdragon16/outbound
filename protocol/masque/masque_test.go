package masque

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go/http3"
	"github.com/daeuniverse/quic-go/quicvarint"
	utls "github.com/refraction-networking/utls"
)

// selfSignedCert generates an in-memory ECDSA certificate.
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

// startH3Proxy serves a minimal MASQUE proxy: plain HTTP/3 CONNECT (TCP echo)
// and extended CONNECT for connect-udp (RFC 9298 datagram echo).
func startH3Proxy(t *testing.T) string { return startH3ProxyWithStatus(t, http.StatusOK) }

func startH3ProxyWithStatus(t *testing.T, connectStatus int) string {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Status must be written before taking the stream over: HTTPStream()
		// flushes, which implicitly commits 200 and swallows later codes.
		if connectStatus != http.StatusOK {
			w.WriteHeader(connectStatus)
			return
		}
		str := w.(http3.HTTPStreamer).HTTPStream()
		// A normal CONNECT keeps Proto "HTTP/3.0"; extended CONNECT carries
		// the :protocol value (RFC 8441 semantics as parsed by quic-go).
		if r.Proto != "HTTP/3.0" {
			w.WriteHeader(http.StatusOK)
			// drain the capsule stream so RESET/FIN state changes surface
			go func() {
				buf := make([]byte, 512)
				for {
					if _, err := str.Read(buf); err != nil {
						return
					}
				}
			}()
			for {
				buf, err := str.ReceiveDatagram(context.Background())
				if err != nil {
					return
				}
				contextID, consumed, err := quicvarint.Parse(buf)
				if err != nil || contextID != 0 {
					return
				}
				out := append(quicvarint.Append(nil, 0), buf[consumed:]...)
				if err := str.SendDatagram(out); err != nil {
					return
				}
			}
		}
		// plain CONNECT: echo the stream payload
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
		Handler:         handler,
		TLSConfig:       &utls.Config{Certificates: []utls.Certificate{selfSignedCert(t)}},
		EnableDatagrams: true,
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close() })
	return pc.LocalAddr().String()
}

func readFull(t *testing.T, c io.Reader, b []byte) {
	t.Helper()
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("read %d bytes: %v", len(b), err)
	}
}

func newTestClient(t *testing.T, proxyAddr string, opts ...Option) *Client {
	t.Helper()
	client, err := NewClient(proxyAddr, "masque.test", true, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestTCPConnect(t *testing.T) {
	client := newTestClient(t, startH3Proxy(t))
	conn, err := client.DialContext(context.Background(), "tcp", "target.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// >16KiB forces multiple HTTP/3 DATA frames on the request stream
	payload := bytes.Repeat([]byte{'x'}, 40000)
	go func() {
		_, _ = conn.Write(payload)
	}()
	got := make([]byte, len(payload))
	readFull(t, conn, got)
	if !bytes.Equal(got, payload) {
		t.Fatal("tcp echo mismatch")
	}
}

func TestTCPUnsupportedNetwork(t *testing.T) {
	client := newTestClient(t, startH3Proxy(t))
	if _, err := client.DialContext(context.Background(), "udp", "target.example.com:443"); err == nil {
		t.Fatal("udp is not a DialContext network here")
	}
}

func TestUDPPacketConn(t *testing.T) {
	client := newTestClient(t, startH3Proxy(t))
	pc, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	targets := []*net.UDPAddr{
		{IP: net.ParseIP("8.8.8.8"), Port: 53},
		{IP: net.ParseIP("2001:db8::1"), Port: 443},
	}
	// each target gets its own CONNECT-UDP flow; labels prove the pairing
	want := make(map[string]string, len(targets))
	for i, target := range targets {
		payload := fmt.Sprintf("flow-%d-payload", i)
		want[target.String()] = payload
		if _, err := pc.WriteTo([]byte(payload), target); err != nil {
			t.Fatalf("write to %v: %v", target, err)
		}
	}
	got := make([]byte, 2048)
	for range targets {
		n, raddr, err := pc.ReadFrom(got)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		expect, ok := want[raddr.String()]
		if !ok {
			t.Fatalf("datagram from unexpected source %v", raddr)
		}
		if string(got[:n]) != expect {
			t.Fatalf("source %v returned %q, want %q", raddr, got[:n], expect)
		}
		delete(want, raddr.String())
	}
	if len(want) != 0 {
		t.Fatalf("missing datagrams from %v", want)
	}

	// a closed packet conn reports the closed state instead of hanging
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pc.ReadFrom(got); err == nil {
		t.Fatal("ReadFrom after Close must fail")
	}
}

func TestDatagramSizeLimit(t *testing.T) {
	client := newTestClient(t, startH3Proxy(t))
	pc, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo(make([]byte, maxDatagramSize+1), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}); err == nil {
		t.Fatal("oversized datagram must be rejected")
	}
}

func TestConnectRejected(t *testing.T) {
	client := newTestClient(t, startH3ProxyWithStatus(t, http.StatusForbidden))
	if _, err := client.DialContext(context.Background(), "tcp", "blocked.example.com:443"); err == nil {
		t.Fatal("rejected CONNECT must return an error")
	}
}

// TestPacketConnDialerOverride stacks MASQUE on an externally supplied UDP
// packet conn routed through a local relay, proving the injection point works.
func TestPacketConnDialerOverride(t *testing.T) {
	backend := startH3Proxy(t)
	relayAddr := startUDPRelay(t, backend)
	var injected atomic.Bool
	client := newTestClient(t, relayAddr, WithPacketConnDialer(func(ctx context.Context, addr string) (net.PacketConn, error) {
		injected.Store(true)
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	}))

	const payload = "through-relay"
	conn, err := client.DialContext(context.Background(), "tcp", "relayed.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	readFull(t, conn, got)
	if string(got) != payload {
		t.Fatalf("got %q", got)
	}
	if !injected.Load() {
		t.Fatal("custom packet conn dialer was not used")
	}
}

// startUDPRelay forwards datagrams between a local socket and dstAddr.
func startUDPRelay(t *testing.T, dstAddr string) string {
	t.Helper()
	dst, err := net.ResolveUDPAddr("udp", dstAddr)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		var clientAddr *net.UDPAddr
		for {
			n, from, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if from.String() == dst.String() {
				if clientAddr != nil {
					_, _ = ln.WriteToUDP(buf[:n], clientAddr)
				}
				continue
			}
			clientAddr = from
			_, _ = ln.WriteToUDP(buf[:n], dst)
		}
	}()
	return ln.LocalAddr().String()
}

func TestUDPPathEncoding(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"8.8.8.8", 443, "/.well-known/masque/udp/8.8.8.8/443/"},
		{"2001:db8::1", 443, "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/"},
		{"proxy.blue.c", 53, "/.well-known/masque/udp/proxy.blue.c/53/"},
	}
	for _, tc := range cases {
		if got := udpPath(tc.host, tc.port); got != tc.want {
			t.Errorf("udpPath(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}
