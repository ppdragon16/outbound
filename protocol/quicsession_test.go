package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	quic "github.com/daeuniverse/quic-go"
	utls "github.com/refraction-networking/utls"
)

// TestZeroRTTSessionCacheResumes pins the transport contract the 0-RTT
// outbounds rely on: with the shared cache a second DialEarly resumes the
// session and is accepted as 0-RTT by the server, and without a cache it never
// is.
func TestZeroRTTSessionCacheResumes(t *testing.T) {
	for _, tt := range []struct {
		name  string
		cache utls.ClientSessionCache
		want  [2]bool
	}{
		{name: "shared cache", cache: ZeroRTTSessionCache(), want: [2]bool{false, true}},
		{name: "no cache", cache: nil, want: [2]bool{false, false}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// A distinct server name keeps the process-wide cache entries of
			// this subtest away from every other caller.
			got := dialUsed0RTT(t, "zerortt."+tt.name+".test", tt.cache)
			if got != tt.want {
				t.Errorf("server-side Used0RTT = %v, want %v", got, tt.want)
			}
		})
	}
}

// dialUsed0RTT starts a 0-RTT capable QUIC server, dials it twice with the
// given cache (opening one stream per connection) and reports whether the
// server accepted early data on each connection.
func dialUsed0RTT(t *testing.T, sni string, cache utls.ClientSessionCache) [2]bool {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &utls.Config{
		Certificates: []utls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		NextProtos:   []string{"h3"},
	}, &quic.Config{Allow0RTT: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan bool, 4)
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func(conn quic.Connection) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				str, err := conn.AcceptStream(ctx)
				if err == nil {
					_, _ = str.Read(make([]byte, 1))
				}
				accepted <- conn.ConnectionState().Used0RTT
				_ = conn.CloseWithError(0, "")
			}(conn)
		}
	}()

	tlsConf := &utls.Config{
		ServerName:         sni,
		NextProtos:         []string{"h3"},
		MinVersion:         utls.VersionTLS13,
		InsecureSkipVerify: true,
		ClientSessionCache: cache,
	}
	var out [2]bool
	for i := range out {
		pconn, err := net.ListenUDP("udp", nil)
		if err != nil {
			t.Fatal(err)
		}
		raddr, err := net.ResolveUDPAddr("udp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := quic.DialEarly(ctx, pconn, raddr, tlsConf, &quic.Config{})
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		str, serr := conn.OpenStreamSync(ctx)
		if serr == nil {
			_, serr = str.Write([]byte("x"))
		}
		select {
		case used := <-accepted:
			out[i] = used
		case <-ctx.Done():
			t.Fatalf("dial %d: server never saw the stream", i)
		}
		if serr != nil && i == 0 {
			// The first attempt must never be an early one (no ticket yet),
			// so a stream error here means the contract changed.
			t.Fatalf("dial %d: stream: %v", i, serr)
		}
		if i == 0 {
			// The ticket is a post-handshake message: keep the connection
			// alive until the client has cached it, otherwise the next dial
			// has nothing to resume from.
			time.Sleep(200 * time.Millisecond)
		}
		_ = conn.CloseWithError(0, "")
		cancel()
		pconn.Close()
	}
	return out
}
