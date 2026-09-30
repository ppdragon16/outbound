package udphop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	quic "github.com/daeuniverse/quic-go"
	utls "github.com/refraction-networking/utls"
)

// TestHopConnCarriesAQuicHandshake pins the integration that broke in
// production: a QUIC handshake through a hop conn whose destination is a custom
// net.Addr. quic-go used to reject that address ("oobConn.WritePacket: address
// is not a *net.UDPAddr") because the conn advertised itself as an
// OOBCapablePacketConn, which routes writes through a raw sockaddr built from
// the dial-time address.
//
// A single-port range keeps the test deterministic; the address type (a port
// range) is what exercises the path.
func TestHopConnCarriesAQuicHandshake(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	serverCert := utls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	const alpn = "hop-test"

	serverPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverPC.Close() })
	ln, err := quic.Listen(serverPC, &utls.Config{
		Certificates: []utls.Certificate{serverCert},
		NextProtos:   []string{alpn},
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			accepted <- err
			return
		}
		accepted <- nil
		_ = conn.CloseWithError(0, "")
	}()

	port := serverPC.LocalAddr().(*net.UDPAddr).Port
	hopAddr, err := ResolveUDPHopAddr(fmt.Sprintf("127.0.0.1:%d-%d", port, port))
	if err != nil {
		t.Fatal(err)
	}
	hConn, err := NewUDPHopPacketConn(hopAddr, time.Hour, func(addr net.Addr) (net.Conn, error) {
		return net.DialUDP("udp", nil, addr.(*net.UDPAddr))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialEarly(ctx, hConn, hopAddr, &utls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("handshake through the hop conn failed: %v", err)
	}
	defer conn.CloseWithError(0, "")
	if err := <-accepted; err != nil {
		t.Fatalf("server side: %v", err)
	}
}
