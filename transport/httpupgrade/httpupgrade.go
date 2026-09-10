package httpupgrade

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/common/ua"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	transportTls "github.com/daeuniverse/outbound/transport/tls"
)

type Dialer struct {
	protocol.StatelessDialer
	tlsConfig  *utls.Config
	addr       string
	host       string
	path       string
	serverName string
	skipVerify bool
	// headers keeps the upgrade handshake's cleartext headers in sync with the
	// impersonated TLS fingerprint. nil means "no fingerprint context" and
	// falls back to the default browser headers at request time.
	headers http.Header
}

// UseFingerprintName makes the upgrade handshake carry the headers a real
// browser with the same fingerprint would send ("chrome_auto", "firefox_120",
// ...). Unknown names fall back to default browser headers.
func (t *Dialer) UseFingerprintName(name string) *Dialer {
	t.headers = transportTls.FingerprintHeaders(name)
	return t
}

func NewDialer(s string, d netproxy.Dialer) (*Dialer, error) {
	u, err := url.Parse(s)
	query := u.Query()
	if err != nil {
		return nil, fmt.Errorf("NewHTTPUpgrade: %w", err)
	}

	path := query.Get("path")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	t := &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: d,
		},
		addr: u.Host,
		path: path,
	}

	if query.Get("allowInsecure") == "true" || query.Get("allowInsecure") == "1" ||
		query.Get("skipVerify") == "true" || query.Get("skipVerify") == "1" {
		t.skipVerify = true
	}

	t.host = query.Get("host")
	if t.host == "" {
		t.host = u.Hostname()
	}

	if u.Scheme == "https" {
		t.serverName = query.Get("serverName")
		if t.serverName == "" {
			t.serverName = u.Hostname()
		}
		t.tlsConfig = &utls.Config{
			ServerName:         t.serverName,
			InsecureSkipVerify: t.skipVerify,
			NextProtos:         []string{"http/1.1"},
		}
	}

	return t, nil
}

func (t *Dialer) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		conn, err := t.ParentDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		if t.tlsConfig != nil {
			conn = utls.Client(conn, t.tlsConfig)
		}

		req, err := http.NewRequest("GET", t.path, nil)
		if err != nil {
			return nil, fmt.Errorf("httpupgrade: %w", err)
		}
		req.Header.Set("Connection", "upgrade")
		req.Header.Set("Upgrade", "websocket")
		// Keep the cleartext handshake consistent with the TLS fingerprint;
		// when no fingerprint context exists, fall back to default browser
		// headers rather than leaving the Go default UA in place.
		headers := t.headers
		if headers == nil {
			headers = ua.Headers(nil)
		}
		for k, v := range headers {
			req.Header[k] = v
		}
		req.Host = t.host

		err = req.Write(conn)
		if err != nil {
			return nil, fmt.Errorf("httpupgrade: %w", err)
		}

		// TODO The bufio usage here is unreliable
		resp, err := http.ReadResponse(bufio.NewReaderSize(conn, 32<<10), req)
		if err != nil {
			return nil, fmt.Errorf("httpupgrade: %w", err)
		}

		if resp.Status == "101 Switching Protocols" &&
			strings.ToLower(resp.Header.Get("Upgrade")) == "websocket" &&
			strings.ToLower(resp.Header.Get("Connection")) == "upgrade" {
			return conn, nil
		}
		return nil, errors.New("httpupgrade: unrecognized reply")

	case "udp":
		return nil, fmt.Errorf("%w: httpupgrade+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: httpupgrade+udp", netproxy.UnsupportedTunnelTypeError)
}
