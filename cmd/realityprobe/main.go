package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	tls "github.com/daeuniverse/outbound/transport/tls"
)

func main() {
	link := os.Args[1]
	u, err := url.Parse(link)
	if err != nil {
		fmt.Println("parse:", err)
		os.Exit(1)
	}
	// 拨号目标是节点地址（link 的 host），不是 sni。
	nodeAddr := u.Host
	if u.Port() == "" {
		nodeAddr = u.Host + ":443"
	}
	x, err := tls.NewReality(link, netproxy.Dialer(direct.Direct))
	if err != nil {
		fmt.Println("NewReality:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := x.DialContext(ctx, "tcp", nodeAddr)
	if err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("OK: REALITY handshake authenticated")
}
