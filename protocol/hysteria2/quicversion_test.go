package hysteria2

import (
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/protocol/hysteria2/client"
	"github.com/daeuniverse/quic-go"
	utls "github.com/refraction-networking/utls"
)

// startUDPBlackhole returns a UDP address and a channel delivering the first
// datagram sent to it, so the QUIC version of the initial packet can be
// asserted without completing a handshake.
func startUDPBlackhole(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	pktCh := make(chan []byte, 4)
	go func() {
		for {
			buf := make([]byte, 4096)
			n, _, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case pktCh <- pkt:
			default:
			}
		}
	}()
	return pc.LocalAddr().String(), pktCh
}

// TestQuicVersionPreference pins that the outbound QUIC v2 preference reaches
// the wire: the default offers v1, and the prefer-v2 version list flipped by
// protocol.QuicVersions produces an RFC 9369 (0x6b3343cf) first packet.
func TestQuicVersionPreference(t *testing.T) {
	for _, tc := range []struct {
		name       string
		versions   []quic.Version
		wantPrefix uint32
	}{
		{"default offers v1", protocol.QuicVersionsHTTP3(0), 0x1},
		{"preferV2 offers v2", protocol.QuicVersionsHTTP3(protocol.Flags_Quic_PreferV2), 0x6b3343cf},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, pktCh := startUDPBlackhole(t)
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &client.Config{
				Addrs:      []net.Addr{udpAddr},
				NextDialer: direct.NewDirectDialer(direct.Option{}),
				Auth:       "user:pass",
				TLSConfig:  utls.Config{ServerName: "hysteria.example.com", InsecureSkipVerify: true},
				QUICConfig: quic.Config{Versions: tc.versions},
			}
			c, err := client.NewClient(cfg)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			// The blackhole never answers, so Connect never completes; only the
			// first flight matters here. Connect bounds itself internally.
			go func() {
				if err := c.Connect(); err != nil {
					t.Logf("connect err: %v", err)
				}
			}()
			defer func() { _ = c.Disconnect() }()

			select {
			case pkt := <-pktCh:
				if len(pkt) < 5 {
					t.Fatal("short packet")
				}
				got := uint32(pkt[1])<<24 | uint32(pkt[2])<<16 | uint32(pkt[3])<<8 | uint32(pkt[4])
				if got != tc.wantPrefix {
					t.Fatalf("first packet version = %#x, want %#x", got, tc.wantPrefix)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no packet captured")
			}
		})
	}
}
