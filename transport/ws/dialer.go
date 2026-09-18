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

	"github.com/daeuniverse/outbound/common/ua"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	transportTls "github.com/daeuniverse/outbound/transport/tls"
	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
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
	protocol.StatelessDialer
	wsAddr              string
	header              http.Header
	tlsClientConfig     *tls.Config
	passthroughUdp      bool
	tlsFragmentation    bool
	fragmentMinLength   int64
	fragmentMaxLength   int64
	fragmentMinInterval int64
	fragmentMaxInterval int64

	wssScheme bool
	// utls fingerprint impersonation for the wss TLS layer. gorilla's own
	// TLS is Go-stdlib-fingerprinted, which CDN-fronted endpoints (CF JA3
	// scoring) single out; when utlsEnabled the wss dial is taken over via
	// NetDialTLSContext and impersonates the chosen browser.
	utlsEnabled bool
	utlsID      utls.ClientHelloID
	// alpn forced to http/1.1 unless the link overrides it: browser
	// fingerprints advertise h2, and a server picking h2 breaks gorilla's
	// HTTP/1.1 upgrade.
	alpn []string
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
	// The V2Ray share format carries the ws path as the "path" query param
	// (e.g. ...&type=ws&path=%2Fcustom), not as the URL path. Without this
	// fallback the dial goes to "/" and CDN-fronted nodes fail the upgrade
	// (301/403) with a bare "websocket: bad handshake".
	if t.Path == "" {
		t.Path = query.Get("path")
	}
	if t.Path != "" && !strings.HasPrefix(t.Path, "/") {
		t.Path = "/" + t.Path
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
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: nextDialer,
		},
		wssScheme:      s.Scheme == "wss",
		wsAddr:         wsUrl.String(),
		passthroughUdp: s.PassthroughUdp,
		header:         http.Header{},
		tlsClientConfig: &tls.Config{
			ServerName:         s.Sni,
			InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure,
		},
	}
	ws.header.Set("Host", s.Hostname)
	// Keep the WebSocket handshake consistent with the impersonated TLS
	// fingerprint: a Chrome ClientHello paired with the Go default UA is
	// linkable across layers.
	if id, err := transportTls.NameToUtlsClientHelloID(option.UtlsImitate); err == nil && id != nil {
		ua.ApplyTo(ws.header, id)
		ws.utlsEnabled = true
		ws.utlsID = *id
	} else {
		ua.ApplyTo(ws.header, nil)
	}
	// Force http/1.1 ALPN: browser ClientHellos advertise h2+h1 and the
	// server would negotiate h2, which gorilla's upgrade cannot speak.
	ws.alpn = []string{"http/1.1"}
	if len(s.Alpn) > 0 {
		ws.alpn = strings.Split(s.Alpn, ",")
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
		rawDial := func(ctx context.Context, addr string) (net.Conn, error) {
			c, err := s.ParentDialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			if s.tlsFragmentation {
				c = transportTls.NewFragmentConn(c, s.fragmentMinLength, s.fragmentMaxLength, s.fragmentMinInterval, s.fragmentMaxInterval)
			}
			return c, nil
		}
		wsDialer := &websocket.Dialer{
			NetDial: func(_, addr string) (net.Conn, error) {
				return rawDial(ctx, addr)
			},
			TLSClientConfig: s.tlsClientConfig,
		}
		// Take the wss TLS layer over with utls when a known fingerprint is
		// configured: NetDialTLSContext replaces gorilla's stdlib-TLS dial
		// entirely (SNI/verify config is carried over below). Without this,
		// the outer TLS is Go-stdlib-fingerprinted no matter what fp= says.
		if s.wssScheme && s.utlsEnabled {

			wsDialer.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := rawDial(ctx, addr)
				if err != nil {
					return nil, err
				}
				serverName := s.tlsClientConfig.ServerName
				if serverName == "" {
					if host, _, serr := net.SplitHostPort(addr); serr == nil {
						serverName = host
					}
				}
				uConn := utls.UClient(c, &utls.Config{
					ServerName:         serverName,
					NextProtos:         s.alpn,
					InsecureSkipVerify: s.tlsClientConfig.InsecureSkipVerify,
					RootCAs:            s.tlsClientConfig.RootCAs,
				}, s.utlsID)
				if err := uConn.HandshakeContext(ctx); err != nil {
					c.Close()
					return nil, err
				}
				return uConn, nil
			}
		}
		rc, _, err := wsDialer.DialContext(ctx, s.wsAddr, s.header)
		if err != nil {
			return nil, fmt.Errorf("[Ws]: dial to %s: %w", s.wsAddr, err)
		}
		return newConn(rc), err
	case "udp":
		if s.passthroughUdp {
			return s.ParentDialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("%w: ws+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Ws) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	if s.passthroughUdp {
		return s.ParentDialer.ListenPacket(ctx, addr)
	}
	return nil, fmt.Errorf("%w: ws+udp", netproxy.UnsupportedTunnelTypeError)
}
