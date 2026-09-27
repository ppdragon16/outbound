package dialer_test

// Connspeed compares cold connection establishment across the QUIC outbounds
// against real server implementations on loopback. Gate it behind CONNCOMP=1
// because it needs the servers started externally, e.g.:
//
//	CONNCOMP=1 go test -count=1 -timeout 300s -run TestConnSpeed ./dialer/ -v
//
// Each attempt builds a *fresh* dialer, so every sample is a full QUIC
// handshake + protocol auth; the "warm" sample dials twice on one dialer to
// show what an established connection adds (stream setup only).

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/hysteria2"
	_ "github.com/daeuniverse/outbound/dialer/juicity"
	_ "github.com/daeuniverse/outbound/dialer/masque"
	_ "github.com/daeuniverse/outbound/dialer/tuic"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	_ "github.com/daeuniverse/outbound/protocol/hysteria2"
	_ "github.com/daeuniverse/outbound/protocol/juicity"
	_ "github.com/daeuniverse/outbound/protocol/tuic"
)

var connSpeedLinks = map[string]string{
	"hy2":     "hysteria2://testpass123@127.0.0.1:18443/?insecure=1&sni=hy2.test",
	"tuic":    "tuic://0af4d518-315d-4980-be5f-22b6e1770d6a:testpass123@127.0.0.1:12444/?congestion_control=bbr&alpn=h3&sni=hy2.test&allow_insecure=1",
	"juicity": "juicity://0af4d518-315d-4980-be5f-22b6e1770d6a:testpass123@127.0.0.1:13444?sni=hy2.test&allow_insecure=1&congestion_control=bbr",
	"masque":  "masque://127.0.0.1:19443?insecure=1&sni=hy2.test",
}

// TestConnSpeed measures, per protocol: the cold dial (QUIC handshake + auth)
// and dial+first-relay-roundtrip, over freshDials fresh dialers, plus one warm
// re-dial on an established connection for reference.
func TestConnSpeed(t *testing.T) {
	if os.Getenv("CONNCOMP") == "" {
		t.Skip("set CONNCOMP=1 (with the loopback servers up) to run the cross-protocol connect benchmark")
	}

	// Relay target: a local echo server the proxies connect back to.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	echoTarget = ln.Addr().String()

	const freshDials = 7
	for name, link := range connSpeedLinks {
		t.Run(name, func(t *testing.T) {
			var dialTimes, totalTimes []time.Duration
			for i := 0; i < freshDials; i++ {
				d := buildDialer(t, link)
				// Lifecycle asymmetry: hy2 establishes the tunnel (handshake
				// + auth) in Connect(); tuic/juicity dial lazily inside
				// DialContext. connectToTunnel returns once the tunnel is
				// usable either way, so the numbers are comparable.
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				start := time.Now()
				conn, dial, err := connectToTunnel(d, ctx)
				if err != nil {
					cancel()
					t.Fatalf("fresh dial %d: %v", i, err)
				}
				dial = time.Since(start)
				total := dial
				if err := roundTrip(conn, echoTarget); err != nil {
					cancel()
					t.Fatalf("fresh dial %d roundtrip: %v", i, err)
				} else {
					total = time.Since(start)
				}
				conn.Close()
				cancel()
				disconnectTunnel(d)
				dialTimes = append(dialTimes, dial)
				totalTimes = append(totalTimes, total)
			}

			// Warm: same dialer, connection already established.
			d := buildDialer(t, link)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if _, _, err := connectToTunnel(d, ctx); err != nil {
				cancel()
				t.Fatalf("warm setup dial: %v", err)
			}
			cancel()
			ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
			start := time.Now()
			conn, err := d.DialContext(ctx2, "tcp", echoTarget)
			if err != nil {
				cancel2()
				t.Fatalf("warm dial: %v", err)
			}
			_ = roundTrip(conn, echoTarget)
			conn.Close()
			cancel2()
			warm := time.Since(start)

			t.Logf("cold dial   median=%v (min %v, max %v) over %d fresh connections",
				median(dialTimes), minOf(dialTimes), maxOf(dialTimes), freshDials)
			t.Logf("cold dial+relay roundtrip median=%v (min %v)", median(totalTimes), minOf(totalTimes))
			t.Logf("warm (existing conn, stream only)   = %v", warm)
		})
	}
}

// connectToTunnel establishes the outbound's tunnel and opens one stream to
// target. It returns (conn, time-to-tunnel, err); time-to-tunnel is the same
// "handshake + auth" span for every protocol despite the different lifecycle
// entry points.
func connectToTunnel(d netproxy.Dialer, ctx context.Context) (net.Conn, time.Duration, error) {
	start := time.Now()
	if c, ok := d.(interface{ Connect() error }); ok {
		if err := c.Connect(); err != nil {
			return nil, 0, err
		}
	}
	conn, err := d.DialContext(ctx, "tcp", echoTarget)
	if err != nil {
		return nil, 0, err
	}
	return conn, time.Since(start), nil
}

func disconnectTunnel(d netproxy.Dialer) {
	if c, ok := d.(interface{ Disconnect() error }); ok {
		_ = c.Disconnect()
	}
}

var echoTarget string

func buildDialer(t *testing.T, link string) netproxy.Dialer {
	t.Helper()
	ds, _, err := dialer.NewFromLink(link)
	if err != nil {
		t.Fatalf("parse %s: %v", link, err)
	}
	if len(ds) != 1 {
		t.Fatalf("link expanded to %d dialers, want 1", len(ds))
	}
	td, err := ds[0].(interface {
		Dialer(*dialer.ExtraOption, netproxy.Dialer) (netproxy.Dialer, error)
	}).Dialer(&dialer.ExtraOption{}, direct.Direct)
	if err != nil {
		t.Fatalf("build dialer: %v", err)
	}
	return td
}

func roundTrip(conn net.Conn, target string) error {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})
	payload := []byte(fmt.Sprintf("ping-%v", time.Now().UnixNano()))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := readFull(conn, got); err != nil {
		return err
	}
	if string(got) != string(payload) {
		return fmt.Errorf("echo mismatch: %q", got)
	}
	return nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		k, err := conn.Read(buf[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func median(xs []time.Duration) time.Duration {
	s := append([]time.Duration(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func minOf(xs []time.Duration) time.Duration {
	m := xs[0]
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}
func maxOf(xs []time.Duration) time.Duration {
	m := xs[0]
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}
