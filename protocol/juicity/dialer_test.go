package juicity

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	tls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

type Params struct {
	Method, Passwd, Address, Port string
}

// Both tests dial a real juicity server (example.com:50001 is a placeholder
// nobody serves on) and cannot pass in offline or CI environments. They are
// manual integration tests: set JUICITY_INTEGRATION=1 and point the address
// below at a live server to run them.
func requireLiveServer(t *testing.T) {
	if os.Getenv("JUICITY_INTEGRATION") == "" {
		t.Skip("integration test against a live juicity server; set JUICITY_INTEGRATION=1 to run")
	}
}

func TestTcp(t *testing.T) {
	requireLiveServer(t)
	d, err := NewDialer(direct.Direct, protocol.Header{
		ProxyAddress: "example.com:50001",
		SNI:          "",
		Feature1:     "bbr",
		TlsConfig:    &tls.Config{NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, ServerName: "aabbcc.com"},
		Cipher:       "",
		User:         "00000000-0000-0000-0000-000000000000",
		Password:     "mypassword",
	})
	if err != nil {
		t.Fatal(err)
	}
	c := http.Client{
		Transport: &http.Transport{DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			t.Log("target", addr)
			c, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			return c, nil
		}},
	}
	resp, err := c.Get("https://ipinfo.io")
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	defer resp.Body.Close()
	t.Log(buf.String())
}

func TestUdp(t *testing.T) {
	requireLiveServer(t)
	d, err := NewDialer(direct.Direct, protocol.Header{
		ProxyAddress: "example.com:50001",
		SNI:          "",
		Feature1:     "bbr",
		TlsConfig:    &tls.Config{NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, ServerName: "aabbcc.com"},
		Cipher:       "",
		User:         "00000000-0000-0000-0000-000000000000",
		Password:     "mypassword",
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if !strings.HasPrefix(network, "udp") {
				return nil, fmt.Errorf("unsupported network")
			}
			c, err := d.DialContext(context.Background(), "udp", address)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
	}
	ips, err := resolver.LookupNetIP(context.TODO(), "ip", "www.baidu.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ips)
}
