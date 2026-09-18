package ws

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Regression: browser fingerprints carry their own ALPN extension (h2 first)
// which overrides Config.NextProtos, so the server negotiated h2 and
// gorilla's HTTP/1.1 upgrade failed with "malformed HTTP response" (the h2
// SETTINGS frame). The dialer must rewrite the ALPN extension before
// handshaking.
func TestFingerprintALPNForcedToHTTP11(t *testing.T) {
	srvCfg := &tls.Config{
		Certificates: []tls.Certificate{mustSelfCert(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		proto string
		err   error
	}
	srvCh := make(chan result, 1)
	go func() {
		srv, err := ln.Accept()
		if err != nil {
			srvCh <- result{err: err}
			return
		}
		defer srv.Close()
		sc := tls.Server(srv, srvCfg)
		if err := sc.Handshake(); err != nil {
			srvCh <- result{err: err}
			return
		}
		srvCh <- result{proto: sc.ConnectionState().NegotiatedProtocol}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	u := utls.UClient(client, &utls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"}, // must NOT be honored as-is
	}, utls.HelloChrome_120)

	// The same rewrite the ws dialer performs.
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	for _, ext := range u.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if err := u.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := u.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated ALPN = %q, want http/1.1", got)
	}
	sr := <-srvCh
	if sr.err != nil {
		t.Fatalf("server: %v", sr.err)
	}
	if sr.proto != "http/1.1" {
		t.Fatalf("server negotiated %q, want http/1.1", sr.proto)
	}
}

func mustSelfCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}
