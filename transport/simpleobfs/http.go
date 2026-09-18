// from https://github.com/Dreamacro/clash/blob/master/component/simple-obfs/http.go

package simpleobfs

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
)

// HTTPObfs is shadowsocks http simple-obfs implementation
type HTTPObfs struct {
	net.Conn
	host          string
	port          string
	path          string
	buf           []byte
	offset        int
	headerBuf     []byte // accumulates the first response until "\r\n\r\n" arrives
	firstRequest  bool
	firstResponse bool
	wMu           sync.Mutex
	rMu           sync.Mutex
}

// maxResponseHeaderSize bounds how many terminator-less bytes the first
// response may accumulate before the peer is declared misbehaving.
const maxResponseHeaderSize = 8192

// CloseWrite forwards the half-close to the inner conn so a relay FIN
// propagates through the obfs layer as a transport FIN.
func (ho *HTTPObfs) CloseWrite() error {
	if cw, ok := ho.Conn.(netproxy.CloseWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (ho *HTTPObfs) Read(b []byte) (int, error) {
	ho.rMu.Lock()
	defer ho.rMu.Unlock()
	if ho.buf != nil {
		n := copy(b, ho.buf[ho.offset:])
		ho.offset += n
		if ho.offset == len(ho.buf) {
			pool.PutBuffer(ho.buf)
			ho.buf = nil
		}
		return n, nil
	}

	if ho.firstResponse {
		for {
			// readFirstResponse: the "\r\n\r\n"-terminated header may straddle
			// TCP segments, and a single read can carry the complete header
			// plus kilobytes of body (the normal fast-relay case). Accumulate
			// into headerBuf, search the JOINED buffer for the terminator
			// BEFORE applying the size bound (a terminator hit is success, not
			// an oversized header), and deliver the body bytes with the read.
			buf := pool.GetBuffer(1 << 15)
			n, err := ho.Conn.Read(buf)
			if err != nil {
				pool.PutBuffer(buf)
				ho.headerBuf = nil
				return 0, err
			}
			ho.headerBuf = append(ho.headerBuf, buf[:n]...)
			pool.PutBuffer(buf)
			idx := bytes.Index(ho.headerBuf, []byte("\r\n\r\n"))
			if idx == -1 {
				if len(ho.headerBuf) > maxResponseHeaderSize {
					ho.headerBuf = nil
					return 0, fmt.Errorf("simple-obfs http: response header exceeds %d bytes", maxResponseHeaderSize)
				}
				continue
			}
			ho.firstResponse = false
			body := ho.headerBuf[idx+4:]
			n = copy(b, body)
			if len(body) > n {
				ho.buf = ho.headerBuf
				ho.offset = idx + 4 + n
			} else {
				pool.PutBuffer(ho.headerBuf)
				ho.headerBuf = nil
			}
			return n, nil
		}
	}
	return ho.Conn.Read(b)
}

func (ho *HTTPObfs) Write(b []byte) (int, error) {
	ho.wMu.Lock()
	defer ho.wMu.Unlock()
	if ho.firstRequest {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s%s", ho.host, ho.path), bytes.NewBuffer(b[:]))
		req.Header.Set("User-Agent", fmt.Sprintf("curl/7.%d.%d", fastrand.Int()%87, fastrand.Int()%2))
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		if ho.port != "80" {
			req.Host = fmt.Sprintf("%s:%s", ho.host, ho.port)
		}
		randBytes := make([]byte, 16)
		fastrand.Read(randBytes)
		req.Header.Set("Sec-WebSocket-Key", base64.URLEncoding.EncodeToString(randBytes))
		req.ContentLength = int64(len(b))
		err := req.Write(ho.Conn)
		ho.firstRequest = false
		return len(b), err
	}

	return ho.Conn.Write(b)
}

// NewHTTPObfs return a HTTPObfs
func NewHTTPObfs(conn net.Conn, host string, port string, path string) net.Conn {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return &HTTPObfs{
		Conn:          conn,
		firstRequest:  true,
		firstResponse: true,
		host:          host,
		port:          port,
		path:          path,
	}
}
