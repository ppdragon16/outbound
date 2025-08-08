package ws

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	transportTls "github.com/daeuniverse/outbound/transport/tls"
	"github.com/gorilla/websocket"
)

func init() {
	dialer.FromLinkRegister("ws", NewWs)
	dialer.FromLinkRegister("wss", NewWs)
}

func parseRange(str string) (min, max int64, err error) {
	stringArr := strings.Split(str, "-")
	if len(stringArr) != 2 {
		return 0, 0, fmt.Errorf("invalid range: %s", str)
	}
	min, err = strconv.ParseInt(stringArr[0], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	max, err = strconv.ParseInt(stringArr[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return min, max, nil
}

// Ws is a base Ws struct
type Ws struct {
	dialer              netproxy.Dialer
	wsAddr              string
	header              http.Header
	tlsClientConfig     *tls.Config
	passthroughUdp      bool
	tlsFragmentation    bool
	fragmentMinLength   int64
	fragmentMaxLength   int64
	fragmentMinInterval int64
	fragmentMaxInterval int64
}

type WsConfig struct {
	Scheme         string
	Host           string
	Path           string
	Hostname       string // Hostname in Http Header
	Alpn           string
	Sni            string
	AllowInsecure  bool
	PassthroughUdp bool
}

// NewWs returns a Ws infra.
func NewWs(link string) (dialer.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewWs: %w", err)
	}

	query := u.Query()

	t := &WsConfig{
		Scheme:   u.Scheme,
		Host:     u.Host,
		Hostname: query.Get("host"),
		Path:     u.Path,
		Alpn:     query.Get("alpn"),
		Sni:      query.Get("sni"),
	}

	if t.Hostname == "" {
		t.Hostname = u.Hostname()
	}
	t.PassthroughUdp, _ = strconv.ParseBool(u.Query().Get("passthroughUdp"))

	if u.Scheme == "wss" {
		t.AllowInsecure, _ = strconv.ParseBool(u.Query().Get("allowInsecure"))
		if !t.AllowInsecure {
			t.AllowInsecure, _ = strconv.ParseBool(u.Query().Get("allow_insecure"))
		}
		if !t.AllowInsecure {
			t.AllowInsecure, _ = strconv.ParseBool(u.Query().Get("allowinsecure"))
		}
		if !t.AllowInsecure {
			t.AllowInsecure, _ = strconv.ParseBool(u.Query().Get("skipVerify"))
		}
	}

	return t, &dialer.Property{
		Name:     u.Fragment,
		Address:  t.Host,
		Protocol: u.Scheme,
		Link:     link,
	}, nil
}

func (s *WsConfig) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, error) {
	wsUrl := url.URL{
		Scheme: s.Scheme,
		Host:   s.Host,
		Path:   s.Path,
	}
	ws := &Ws{
		dialer:         nextDialer,
		wsAddr:         wsUrl.String(),
		passthroughUdp: s.PassthroughUdp,
		header:         http.Header{},
		tlsClientConfig: &tls.Config{
			ServerName:         s.Sni,
			InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure,
		},
	}
	ws.header.Set("Host", s.Hostname)
	if len(s.Alpn) > 0 {
		ws.tlsClientConfig.NextProtos = strings.Split(s.Alpn, ",")
	}
	if option.TlsFragment {
		ws.tlsFragmentation = true
		minLen, maxLen, err := parseRange(option.TlsFragmentLength)
		if err != nil {
			return nil, err
		}
		ws.fragmentMinLength = minLen
		ws.fragmentMaxLength = maxLen
		minInterval, maxInterval, err := parseRange(option.TlsFragmentInterval)
		if err != nil {
			return nil, err
		}
		ws.fragmentMinInterval = minInterval
		ws.fragmentMaxInterval = maxInterval
	}
	return ws, nil
}

func (s *Ws) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		wsDialer := &websocket.Dialer{
			NetDial: func(_, addr string) (net.Conn, error) {
				c, err := s.dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}

				if s.tlsFragmentation {
					c = transportTls.NewFragmentConn(c, s.fragmentMinLength, s.fragmentMaxLength, s.fragmentMinInterval, s.fragmentMaxInterval)
				}

				return c, nil
			},
			TLSClientConfig: s.tlsClientConfig,
		}
		rc, _, err := wsDialer.DialContext(ctx, s.wsAddr, s.header)
		if err != nil {
			return nil, fmt.Errorf("[Ws]: dial to %s: %w", s.wsAddr, err)
		}
		return newConn(rc), err
	case "udp":
		if s.passthroughUdp {
			return s.dialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("%w: ws+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Ws) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	if s.passthroughUdp {
		return s.dialer.ListenPacket(ctx, addr)
	}
	return nil, fmt.Errorf("%w: ws+udp", netproxy.UnsupportedTunnelTypeError)
}
