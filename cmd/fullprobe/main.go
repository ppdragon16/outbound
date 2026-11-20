package main

// 全链路探针：从节点链接构建拨号器，经代理完成 TCP+TLS+HTTP，
// 支持大流量下载，用于验证 vision 数据面在真实负载下的稳定性。
// 用法: fullprobe <link> <target:port> <sni> <path> [bytesToRead]
import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	_ "github.com/daeuniverse/outbound/protocol/vless"
)

func main() {
	link, target, sni, path := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	want := 1024
	if len(os.Args) > 5 {
		want, _ = strconv.Atoi(os.Args[5])
	}
	ds, prop, err := D.NewFromLink(link)
	if err != nil {
		fmt.Println("NewFromLink:", err)
		os.Exit(1)
	}
	fmt.Println("node:", prop.Name, "|", prop.Protocol, "|", prop.Address)
	var d netproxy.Dialer = direct.Direct
	opt := &D.ExtraOption{}
	for _, nd := range ds {
		if d, err = nd.Dialer(opt, d); err != nil {
			fmt.Println("build dialer:", err)
			os.Exit(1)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		fmt.Println("FAIL dial:", err)
		os.Exit(1)
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{ServerName: sni, NextProtos: []string{"http/1.1"}})
	if err := tc.HandshakeContext(ctx); err != nil {
		fmt.Println("FAIL tls:", err)
		os.Exit(1)
	}
	fmt.Println("OK: TLS through proxy")
	if up := os.Getenv("DAE_UPLOAD_BYTES"); up != "" {
		n, _ := strconv.Atoi(up)
		hdr := "POST " + path + " HTTP/1.1\r\nHost: " + sni + "\r\nContent-Length: " + strconv.Itoa(n) + "\r\nConnection: close\r\n\r\n"
		body := make([]byte, 32*1024)
		for i := range body {
			body[i] = byte('a' + i%26)
		}
		if _, err := tc.Write([]byte(hdr)); err != nil {
			fmt.Println("FAIL write head:", err)
			os.Exit(1)
		}
		sent := 0
		for sent < n {
			chunk := body
			if n-sent < len(chunk) {
				chunk = chunk[:n-sent]
			}
			if _, err := tc.Write(chunk); err != nil {
				fmt.Printf("FAIL upload after %d/%d bytes: %v\n", sent, n, err)
				os.Exit(1)
			}
			sent += len(chunk)
		}
		fmt.Println("OK: uploaded", sent, "bytes")
	}
	if os.Getenv("DAE_UPLOAD_BYTES") == "" {
		req := "GET " + path + " HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n"
		if _, err := tc.Write([]byte(req)); err != nil {
			fmt.Println("FAIL write:", err)
			os.Exit(1)
		}
	}
	total := 0
	buf := make([]byte, 32*1024)
	start := time.Now()
	tc.SetReadDeadline(time.Now().Add(60 * time.Second))
	for total < want {
		n, err := tc.Read(buf)
		total += n
		if err != nil {
			var nerr net.Error
			if ok := isTemporary(err, &nerr); ok {
				continue
			}
			fmt.Printf("FAIL read after %d bytes: %v\n", total, err)
			os.Exit(1)
		}
	}
	fmt.Printf("OK: received %d bytes in %v (%.1f KB/s)\n", total, time.Since(start).Round(time.Millisecond),
		float64(total)/1024/time.Since(start).Seconds())
}

func isTemporary(err error, out *net.Error) bool {
	ne, ok := err.(net.Error)
	if ok && ne.Timeout() {
		*out = ne
		return true
	}
	return false
}
