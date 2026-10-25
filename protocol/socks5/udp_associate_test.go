package socks5

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// assocCapture is what the fake server saw in one request.
type assocCapture struct {
	cmd byte
	dst socks.Addr
}

// startAssocServer runs a minimal no-auth SOCKS5 server. It completes the
// greeting, captures the first request's CMD and DST.ADDR/DST.PORT, replies
// success with BND pointing at the given UDP relay, and then just holds the
// control conn open, as a real server would while the association is alive.
func startAssocServer(t *testing.T, ctrlHost string, relay *net.UDPAddr) (ctrlAddr string, captured <-chan assocCapture, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", ctrlHost+":0")
	if err != nil {
		t.Fatalf("listen control: %v", err)
	}
	ch := make(chan assocCapture, 1)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Greeting: VER NMETHODS, methods...; reply "no auth required".
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		methods := make([]byte, hdr[1])
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		if _, err := conn.Write([]byte{5, 0}); err != nil {
			return
		}
		// Request: VER CMD RSV + DST.ADDR/DST.PORT.
		head := make([]byte, 3)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		dst, err := socks.ReadAddr(conn, make([]byte, socks.MaxAddrLen))
		if err != nil {
			return
		}
		ch <- assocCapture{cmd: head[1], dst: dst}
		// Reply: success, BND = the UDP relay address, in its own family.
		var bnd []byte
		if ip4 := relay.IP.To4(); ip4 != nil {
			bnd = []byte{5, 0, 0, socks.ATypIP4}
			bnd = append(bnd, ip4...)
		} else {
			bnd = []byte{5, 0, 0, socks.ATypIP6}
			bnd = append(bnd, relay.IP.To16()...)
		}
		bnd = append(bnd, byte(relay.Port>>8), byte(relay.Port))
		conn.Write(bnd)
		// Hold the control conn open; ListenPacket keeps using it.
		<-release
	}()
	return ln.Addr().String(), ch, func() {
		ln.Close()
		close(release)
		<-done
	}
}

// TestUDPAssociateDeclaresZeroSource pins the wire format of the UDP
// ASSOCIATE request. Per RFC 1928 section 7 its DST.ADDR/DST.PORT carries the
// address the client expects to send UDP datagrams *from*, and a server MAY
// use it to restrict the association — it is not the proxy target. dae cannot
// know its post-NAT source, so it must send the all-zeros form: filling in the
// target made source-checking servers drop every proxied datagram while DNS
// kept working through its TCP fallback (daeuniverse/dae#1144).
//
// Both address families dial the control connection, and both must carry the
// same IPv4 all-zeros DST: the unspecified form is family-agnostic on the
// wire (a compliant server cannot use it to restrict anything, and falls back
// to comparing the datagram source against the control connection's peer),
// and it must not grow family awareness of the transport.
func TestUDPAssociateDeclaresZeroSource(t *testing.T) {
	for name, cfg := range map[string]struct{ ctrlHost, relayAddr string }{
		"ipv4": {ctrlHost: "127.0.0.1", relayAddr: "127.0.0.1:0"},
		"ipv6": {ctrlHost: "[::1]", relayAddr: "[::1]:0"},
	} {
		t.Run(name, func(t *testing.T) {
			relay, err := net.ListenPacket("udp", cfg.relayAddr)
			if err != nil {
				t.Fatalf("bind relay: %v", err)
			}
			defer relay.Close()

			ctrlAddr, captured, stop := startAssocServer(t, cfg.ctrlHost, relay.LocalAddr().(*net.UDPAddr))
			defer stop()

			d, err := NewSocks5("socks5://"+ctrlHostJoin(cfg.ctrlHost, ctrlAddr), direct.Direct)
			if err != nil {
				t.Fatalf("NewSocks5: %v", err)
			}
			pc, err := d.ListenPacket(context.Background(), "8.8.8.8:53")
			if err != nil {
				t.Fatalf("ListenPacket: %v", err)
			}
			defer pc.Close()

			select {
			case got := <-captured:
				if got.cmd != socks.CmdUDPAssociate {
					t.Fatalf("request CMD = %d, want UDP ASSOCIATE (%d)", got.cmd, socks.CmdUDPAssociate)
				}
				if got.dst.String() != "0.0.0.0:0" {
					t.Fatalf("UDP ASSOCIATE DST = %s, want 0.0.0.0:0 (the target must not be sent as the association source)", got.dst.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for the fake server to see the ASSOCIATE request")
			}
		})
	}
}

// ctrlHostJoin merges the control host with the listener's host:port. The
// port is the only variable part; the host pins the dial family.
func ctrlHostJoin(host, listenAddr string) string {
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return host + ":0"
	}
	return host + ":" + port
}
