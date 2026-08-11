package tls

import (
	"context"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

// Tls is a base Tls struct
type Tls struct {
	protocol.StatelessDialer
	addr                string
	tlsImplentation     string
	passthroughUdp      bool
	fragmentation       bool
	fragmentMinLength   int64
	fragmentMaxLength   int64
	fragmentMinInterval int64
	fragmentMaxInterval int64

	tlsConfig  *utls.Config
	utlsConfig *utls.Config
	utlsID     *utls.ClientHelloID
}

type TLSConfig struct {
	Host           string
	Sni            string
	Alpn           string
	PassthroughUdp bool

	AllowInsecure bool
}

// NewTls returns a Tls infra.
func (s *TLSConfig) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, error) {
	t := &Tls{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: nextDialer,
		},
		addr:            s.Host,
		tlsImplentation: option.TlsImplementation,
		passthroughUdp:  s.PassthroughUdp,
	}
	if s.Sni == "" {
		host, _, err := net.SplitHostPort(s.Host)
		if err != nil {
			return nil, err
		}
		s.Sni = host
	}
	t.tlsConfig = &utls.Config{
		ServerName:         s.Sni,
		InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure,
	}
	if len(s.Alpn) > 0 {
		t.tlsConfig.NextProtos = strings.Split(s.Alpn, ",")
	}

	if option.TlsFragment {
		t.fragmentation = true
		minLen, maxLen, err := parseRange(option.TlsFragmentLength)
		if err != nil {
			return nil, err
		}
		t.fragmentMinLength = minLen
		t.fragmentMaxLength = maxLen
		minInterval, maxInterval, err := parseRange(option.TlsFragmentInterval)
		if err != nil {
			return nil, err
		}
		t.fragmentMinInterval = minInterval
		t.fragmentMaxInterval = maxInterval
	}
	if option.TlsImplementation == "utls" {
		utlsID, err := nameToUtlsClientHelloID(option.UtlsImitate)
		if err != nil {
			return nil, err
		}
		t.utlsID = utlsID
		t.utlsConfig = &utls.Config{
			ServerName:         s.Sni,
			InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure,
			NextProtos:         t.tlsConfig.NextProtos,
			// 内存优化：只保留成熟、低分配的传统曲线
			CurvePreferences: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			},
		}
	}
	return t, nil
}

func (s *Tls) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		rc, err := s.ParentDialer.DialContext(ctx, network, s.addr)
		if err != nil {
			return nil, fmt.Errorf("[Tls]: dial to %s: %w", s.addr, err)
		}

		if s.fragmentation {
			rc = NewFragmentConn(rc, s.fragmentMinLength, s.fragmentMaxLength, s.fragmentMinInterval, s.fragmentMaxInterval)
		}

		var tlsConn interface {
			net.Conn
			Handshake() error
		}

		switch s.tlsImplentation {
		case "tls":
			tlsConn = utls.Client(rc, s.tlsConfig)

		case "utls":
			tlsConn = utls.UClient(rc, s.utlsConfig, *s.utlsID)

		default:
			rc.Close()
			return nil, fmt.Errorf("unknown tls implementation: %v", s.tlsImplentation)
		}

		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			rc.Close()
			return nil, err
		}
		return tlsConn, err
	case "udp":
		if s.passthroughUdp {
			return s.ParentDialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Tls) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	if s.passthroughUdp {
		return s.ParentDialer.ListenPacket(ctx, addr)
	}
	return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
}
