package http

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	tls2 "github.com/daeuniverse/outbound/transport/tls"
	"github.com/samber/oops"
)

// HttpProxy is an HTTP/HTTPS proxy.
type HttpProxy struct {
	https     bool
	transport bool
	Addr      string
	Host      string
	Path      string
	HaveAuth  bool
	Username  string
	Password  string
	dialer    netproxy.Dialer
}

func NewHTTPProxy(u *url.URL, option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, error) {
	s := &HttpProxy{
		dialer: nextDialer,
		Addr:   u.Host,
		Path:   u.Path,
		Host:   u.Query().Get("host"),
	}
	if !strings.HasPrefix(s.Path, "/") {
		s.Path = "/" + s.Path
	}

	if u.User != nil {
		s.HaveAuth = true
		s.Username = u.User.Username()
		s.Password, _ = u.User.Password()
	}

	s.transport, _ = strconv.ParseBool(u.Query().Get("transport"))

	if u.Scheme == "https" {
		s.https = true
		alpn := u.Query().Get("alpn")
		if alpn == "" {
			alpn = "h2,http/1.1"
		}
		allowInsecure, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(u.Query().Get("allow_insecure"))
		}
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(u.Query().Get("allowinsecure"))
		}
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(u.Query().Get("skipVerify"))
		}
		tlsConfig := tls2.TLSConfig{
			Host:          u.Host,
			Alpn:          alpn,
			Sni:           u.Query().Get("sni"),
			AllowInsecure: allowInsecure,
		}
		var err error
		if s.dialer, err = tlsConfig.Dialer(option, nextDialer); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *HttpProxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp":
		return NewConn(s.dialer, s, addr, network), nil
	default:
		return nil, oops.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *HttpProxy) ListenPacket(ctx context.Context, network string) (net.PacketConn, error) {
	return nil, oops.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
}
