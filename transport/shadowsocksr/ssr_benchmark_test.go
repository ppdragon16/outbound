package shadowsocksr

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/protocol/shadowsocks_stream"
	"github.com/daeuniverse/outbound/transport/shadowsocksr/obfs"
	"github.com/daeuniverse/outbound/transport/shadowsocksr/proto"
)

func BenchmarkSSR(b *testing.B) {
	b.N = 5000
	for i := 0; i < b.N; i++ {
		d := direct.NewDirectDialer(direct.Option{})
		obfsDialer, err := obfs.NewDialer(d, &obfs.ObfsParam{
			ObfsHost:  "",
			ObfsPort:  0,
			Obfs:      "tls1.2_ticket_auth",
			ObfsParam: "",
		})
		if err != nil {
			b.Fatal(err)
		}
		d = obfsDialer
		d, err = shadowsocks_stream.NewDialer(d, protocol.Header{
			ProxyAddress: "127.0.0.1:8989",
			Cipher:       "aes-256-cfb",
			Password:     "p@ssw0rd",
			Flags:        0,
		})
		if err != nil {
			b.Fatal(err)
		}
		d = &proto.Dialer{
			NextDialer:    d,
			Protocol:      "auth_chain_a",
			ProtocolParam: "",
			ObfsOverhead:  obfsDialer.ObfsOverhead(),
		}

		c := http.Client{
			Transport: &http.Transport{Dial: func(network string, addr string) (net.Conn, error) {
				return d.DialContext(context.Background(), "tcp", addr)
			}},
		}
		resp, err := c.Get("https://httpbin.org/ip")
		if err != nil {
			b.Fatal(err)
		}
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		defer resp.Body.Close()
		b.Log(buf.String())
	}
}
