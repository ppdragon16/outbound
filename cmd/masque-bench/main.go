// Command masque-bench measures a MASQUE relay directly, without a proxy
// client in the path: single- and multi-stream download/upload rates and the
// dial latency (cold and warm).
//
// Build it from this checkout (replace directives don't propagate, so
// `go install pkg@version` cannot build it):
//
//	go build -o masque-bench ./cmd/masque-bench
//
// Then point it at the same relay a dae link uses:
//
//	./masque-bench -proxy '[2001:db8::1]:7443' -sni example.com -mtu 1440
//	./masque-bench -proxy 203.0.113.7:7443 -par 8        # aggregate, browser-like
//	./masque-bench -proxy 203.0.113.7:7443 -up -par 4    # upload
//
// The default target is speed.cloudflare.com, which serves /__down?bytes=N and
// /__up; override with -target/-path to measure against your own server.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	masque "github.com/daeuniverse/outbound/protocol/masque"
)

// clientDialer adapts the raw masque client to a DialContext/ListenPacket pair.
type clientDialer struct{ *masque.Client }

func (d *clientDialer) Connect() error    { return nil }
func (d *clientDialer) Disconnect() error { return nil }
func (d *clientDialer) Alive() bool       { return true }
func (d *clientDialer) ListenPacket(ctx context.Context, _ string) (net.PacketConn, error) {
	return d.Client.ListenPacket(ctx)
}

func main() {
	proxy := flag.String("proxy", "", "relay address as host:port (required)")
	sni := flag.String("sni", "", "TLS SNI (default: the proxy host)")
	insecure := flag.Bool("insecure", true, "skip certificate verification")
	mtu := flag.Int("mtu", 0, "QUIC Initial packet size (path MTU budget); 0 keeps the safe default 1280")
	cc := flag.String("cc", "", `congestion control: "" (BBRv3) or "bbr"`)
	zeroRTT := flag.Bool("zero-rtt", false, "use QUIC 0-RTT on a resumed session")
	par := flag.Int("par", 1, "parallel streams (a browser speed test opens several)")
	duration := flag.Duration("duration", 10*time.Second, "measurement window")
	up := flag.Bool("up", false, "measure upload instead of download")
	target := flag.String("target", "speed.cloudflare.com:80", "target host:port reached through the relay")
	path := flag.String("path", "", "HTTP path (default /__down?bytes=20000000, or /__up with -up)")
	flag.Parse()
	if *proxy == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *path == "" {
		if *up {
			*path = "/__up"
		} else {
			*path = "/__down?bytes=20000000"
		}
	}

	var opts []masque.Option
	if *mtu > 0 {
		opts = append(opts, masque.WithMTU(*mtu))
	}
	if *cc != "" {
		opts = append(opts, masque.WithCongestionControl(*cc))
	}
	if *zeroRTT {
		opts = append(opts, masque.WithZeroRTT())
	}
	c, err := masque.NewClient(*proxy, *sni, *insecure, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "masque:", err)
		os.Exit(1)
	}
	defer c.Close()
	d := &clientDialer{c}

	// Cold and warm dial latency: the first dial pays the QUIC handshake, the
	// second reuses the connection.
	for i := 0; i < 2; i++ {
		start := time.Now()
		conn, err := d.DialContext(context.Background(), "tcp", *target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dial[%d]: %v\n", i, err)
			os.Exit(1)
		}
		fmt.Printf("dial[%d]: %v\n", i, time.Since(start).Round(100*time.Microsecond))
		_ = conn.Close()
	}

	counter := &byteCounter{}
	start := time.Now()
	deadline := start.Add(*duration)
	errs := make(chan error, *par)
	for i := 0; i < *par; i++ {
		go func() {
			errs <- transfer(d, *target, *path, *up, deadline, counter)
		}()
	}
	for i := 0; i < *par; i++ {
		if err := <-errs; err != nil {
			fmt.Fprintf(os.Stderr, "stream: %v\n", err)
		}
	}
	elapsed := time.Since(start)
	b := counter.Load()
	dir := "down"
	if *up {
		dir = "up"
	}
	fmt.Printf("%s par=%d: %.2f MB in %v -> %.2f MB/s (%.1f Mbps)\n",
		dir, *par, float64(b)/1e6, elapsed.Round(time.Millisecond), float64(b)/elapsed.Seconds()/1e6, float64(b)*8/elapsed.Seconds()/1e6)
}
