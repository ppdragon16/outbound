package tuic_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	quic "github.com/daeuniverse/quic-go"

	tuiclink "github.com/daeuniverse/outbound/dialer/tuic"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

// TestE2EZeroRTTHandshakeResumes drives the opted-in path against a spec
// server that allows 0-RTT: the first connection authenticates on a fresh
// handshake, the second one resumes from the ticket (visible server-side as
// Used0RTT) and must authenticate just as well - the token is derived from the
// completed handshake either way, which is what makes resumption safe.
func TestE2EZeroRTTHandshakeResumes(t *testing.T) {
	addr, obs := startSpecServerCfg(t, e2ePass, []string{"h3"}, &quic.Config{Allow0RTT: true})
	d := newClientFull(t, addr, e2eUUID, e2ePass, []string{"h3"}, protocol.Flags_Quic_ZeroRTT)

	for attempt := 0; attempt < 2; attempt++ {
		if attempt == 1 {
			// The ticket is a post-handshake message; give the first
			// connection a moment to cache it before resuming.
			time.Sleep(200 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
		_, dialErr := d.DialContext(ctx, "tcp", "1.1.1.1:53")
		cancel()
		select {
		case o := <-obs:
			if o.err != nil {
				t.Fatalf("attempt %d: server could not parse AUTH: %v", attempt, o.err)
			}
			if !o.tokenMatch {
				t.Fatalf("attempt %d: token mismatch (auth would fail)", attempt)
			}
			if want := attempt == 1; o.used0RTT != want {
				t.Fatalf("attempt %d: used0RTT = %v, want %v", attempt, o.used0RTT, want)
			}
		case <-time.After(authTimeout):
			t.Fatalf("attempt %d: server never saw an AUTH stream", attempt)
		}
		_ = dialErr // the spec server closes every connection after AUTH
	}
}

// dnsQuery is a minimal A query for example.com, length-prefixed the way
// DNS-over-TCP expects (the same bytes dae's connectivity check sends).
var dnsQuery = []byte{
	0x00, 0x1d, 0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
}

// liveDial builds a fresh dialer from the link and runs one dial + DNS-over-TCP
// round trip through the proxy, returning how long dial-to-answer took. A
// fresh dialer per attempt means a fresh client ring, i.e. a fresh QUIC
// handshake every time - the path a reconnecting dae node takes. The target is
// a public resolver because the tunnel egress is the remote proxy, not this
// host.
func liveDial(t *testing.T, link string) (time.Duration, error) {
	t.Helper()
	d0, _, err := tuiclink.NewTuic(link)
	if err != nil {
		t.Fatalf("NewTuic: %v", err)
	}
	td, err := d0.(interface {
		Dialer(*dialer.ExtraOption, netproxy.Dialer) (netproxy.Dialer, error)
	}).Dialer(&dialer.ExtraOption{}, direct.Direct)
	if err != nil {
		t.Fatalf("Tuic.Dialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := td.DialContext(ctx, "tcp", "1.1.1.1:53")
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if _, err := conn.Write(dnsQuery); err != nil {
		return 0, err
	}
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return 0, err
	}
	if n < 17 { // 2-byte length prefix + a minimal DNS header + some answer
		return 0, fmt.Errorf("short DNS response (%d bytes)", n)
	}
	if plen := int(resp[0])<<8 | int(resp[1]); n-2 != plen {
		return 0, fmt.Errorf("DNS length prefix %d does not match %d read bytes", plen, n-2)
	}
	return time.Since(start), nil
}

// TestE2ELiveZeroRTTHandshake A/B times the opted-in link against a real
// sing-box tuic inbound: the same link with and without zero_rtt_handshake,
// three fresh handshakes each. The zero_rtt variants must all work (the
// resumed connection authenticates through the completed-handshake exporter);
// the timings show what resumption actually buys on this link.
func TestE2ELiveZeroRTTHandshake(t *testing.T) {
	proxyAddr := os.Getenv("TUICE2E_ADDR")
	if proxyAddr == "" {
		t.Skip("set TUICE2E_ADDR=<host:port> to run against a real sing-box tuic inbound")
	}

	base := "tuic://0af4d518-315d-4980-be5f-22b6e1770d6a:0af4d518-315d-4980-be5f-22b6e1770d6a@%s?insecure=1&sni=www.linux.com&congestion_control=bbr&quicv2=1"
	for _, tt := range []struct {
		name string
		link string
	}{
		{"plain", fmt.Sprintf(base, proxyAddr)},
		{"zero_rtt", fmt.Sprintf(base+"&zero_rtt_handshake=1", proxyAddr)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 3; i++ {
				d, err := liveDial(t, tt.link)
				if err != nil {
					t.Fatalf("attempt %d: %v", i, err)
				}
				t.Logf("attempt %d: dial+auth+relay = %v", i, d)
			}
		})
	}
}
