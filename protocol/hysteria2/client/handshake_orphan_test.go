package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	utls "github.com/refraction-networking/utls"
)

// startRejectingAuthServer serves a hysteria2 auth endpoint that completes the
// QUIC handshake and then rejects the request, so the client fails after the
// connection exists. It hands out the accepted connection so a test can watch
// when the client releases it.
func startRejectingAuthServer(t *testing.T) (string, <-chan quic.Connection) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hysteria-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		DNSNames:     []string{"hysteria"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := http3.ConfigureTLSConfig(&utls.Config{
		Certificates: []utls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}),
		TLSConfig:       tlsConf,
		EnableDatagrams: true,
	}
	t.Cleanup(func() { _ = srv.Close() })

	accepted := make(chan quic.Connection, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		accepted <- conn
		_ = srv.ServeQUICConn(conn)
	}()
	return ln.Addr().String(), accepted
}

// TestFailedHandshakeReleasesTheEstablishedConnection pins that a connection
// established by a failed handshake attempt is closed before tryHandshake
// returns.
//
// The caller owns only the packet conn, so an orphaned connection would keep
// its run loop writing to a socket that is closed moments later: quic-go then
// destroys it with a raw "use of closed network connection" (and the fd plus
// goroutines survive until the idle timeout). The losing half of every
// happy-eyeballs race hits exactly this path, which is why the airport-log
// noise looked like a transport failure.
func TestFailedHandshakeReleasesTheEstablishedConnection(t *testing.T) {
	addr, accepted := startRejectingAuthServer(t)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(&Config{
		Addrs:      []net.Addr{udpAddr},
		NextDialer: direct.NewDirectDialer(direct.Option{}),
		Auth:       "wrong-password",
		TLSConfig:  utls.Config{ServerName: "hysteria", InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Disconnect() })

	if err := c.Connect(); err == nil {
		t.Fatal("a rejected authentication must fail the connect")
	}

	var srvConn quic.Connection
	select {
	case srvConn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never accepted a QUIC connection")
	}
	// Keep-alives are enabled, so an orphan would stay alive here rather than
	// time out; only an explicit close ends it.
	select {
	case <-srvConn.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the client left the QUIC connection open after the failed handshake")
	}
}
