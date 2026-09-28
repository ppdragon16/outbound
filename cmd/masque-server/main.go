// masque-server is a standalone reference MASQUE proxy server (RFC 9298
// CONNECT-UDP + plain HTTP/3 CONNECT) for outbound's masque client. It exists
// because no mainstream proxy core ships a masque *server*; see
// protocol/masque/server for the implementation and its caveats.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/protocol/masque/server"
)

func main() {
	listen := flag.String("listen", ":443", "UDP listen address")
	certFile := flag.String("cert", "", "TLS certificate (PEM)")
	keyFile := flag.String("key", "", "TLS private key (PEM)")
	idle := flag.Duration("idle-timeout", 5*time.Minute, "UDP flow idle timeout")
	mtu := flag.Int("mtu", 0, "QUIC Initial packet size (path MTU budget); 0 = safe default 1280, 1452 for 1500-MTU paths")
	allowTargets := flag.String("allow-targets", "", "comma-separated CIDRs of relayable targets; empty allows all (open relay!)")
	verbose := flag.Bool("v", false, "log every relayed target")
	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		log.Fatal("-cert and -key are required")
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load certificate: %v", err)
	}

	var allow func(string, netip.AddrPort) error
	if *allowTargets != "" {
		var filters []netip.Prefix
		for _, entry := range splitComma(*allowTargets) {
			p, err := netip.ParsePrefix(entry)
			if err != nil {
				single, err2 := netip.ParseAddr(entry)
				if err2 != nil {
					log.Fatalf("parse -allow-targets entry %q: %v", entry, err)
				}
				p = netip.PrefixFrom(single, single.BitLen())
			}
			filters = append(filters, p)
		}
		allow = func(_ string, addr netip.AddrPort) error {
			ip := addr.Addr()
			if ip.Is4In6() {
				ip = ip.Unmap()
			}
			for _, p := range filters {
				if p.Contains(ip) {
					return nil
				}
			}
			return errTargetDenied
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if !*verbose {
		logger = slog.New(slog.DiscardHandler)
	}

	srv, err := server.New(server.Config{
		Certificate:       utls.Certificate{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey},
		IdleTimeout:       *idle,
		InitialPacketSize: *mtu,
		AllowTarget:       allow,
		Logger:            logger,
	})
	if err != nil {
		log.Fatalf("build server: %v", err)
	}
	pc, err := net.ListenUDP("udp", udpAddr(*listen))
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	logger.Info("masque-server listening", "addr", pc.LocalAddr().String())
	if err := srv.Serve(pc); err != nil {
		log.Fatal(err)
	}
}

type errTargetDeniedType struct{}

func (errTargetDeniedType) Error() string { return "target not in -allow-targets" }

var errTargetDenied error = errTargetDeniedType{}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func udpAddr(addr string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("resolve -listen: %v", err)
	}
	return a
}
