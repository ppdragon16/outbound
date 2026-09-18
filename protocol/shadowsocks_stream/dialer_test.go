package shadowsocks_stream

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

type Params struct {
	Method, Passwd, Address, Port string
}

func requireLiveServer(t *testing.T) {
	if os.Getenv("OUTBOUND_LIVE_SERVER_TESTS") == "" {
		t.Skip("integration test against a live proxy server; set the env var to run")
	}
}

// https://github.com/winterssy/SSR-Docker
func TestNewSSStream(t *testing.T) {
	requireLiveServer(t)

	params := Params{
		Method:  "aes-256-cfb",
		Passwd:  "p@ssw0rd",
		Address: "localhost",
		Port:    "8989",
	}
	dialer, err := NewDialer(direct.NewDirectDialer(direct.Option{}), protocol.Header{
		Cipher:       params.Method,
		Password:     params.Passwd,
		ProxyAddress: net.JoinHostPort(params.Address, params.Port),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := http.Client{
		Transport: &http.Transport{Dial: func(network string, addr string) (net.Conn, error) {
			return dialer.DialContext(context.Background(), "tcp", addr)
		}},
	}
	resp, err := c.Get("https://www.baidu.com")
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	defer resp.Body.Close()
	t.Log(buf.String())
}
