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
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
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

// TestDialerEndToEnd exercises the netproxy.Dialer surface against a real
// HTTP/3 CONNECT proxy.
func TestDialerEndToEnd(t *testing.T) {
	addr := startEchoProxy(t)
	d, err := NewDialer(nil, addr, "masque.test", true, false)
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

	if _, err := d.DialContext(context.Background(), "udp", "x:1"); err == nil {
		t.Fatal("non-tcp network must be rejected")
	}

	pc, err := d.ListenPacket(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
}

func TestDialerRequiresAddress(t *testing.T) {
	if _, err := NewDialer(nil, "", "", false, false); err == nil {
		t.Fatal("empty address must be rejected")
	}
}

// startEchoProxy serves plain HTTP/3 CONNECT with an echo tunnel.
func startEchoProxy(t *testing.T) string {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
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
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close() })
	return pc.LocalAddr().String()
}

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
