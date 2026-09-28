package masque

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	dialer.FromLinkRegister("masque", NewMasque)
}

// Masque is the config-level representation of a MASQUE proxy, parsed from a
// masque://host:port?peer=&insecure=1#name link.
type Masque struct {
	link     string
	Name     string
	Host     string
	Sni      string
	Insecure bool
	// QuicV2 offers QUIC v2 (RFC 9369) in the first packet.
	QuicV2 bool
	// ZeroRTT sends the first CONNECT / CONNECT-UDP request as QUIC 0-RTT
	// early data on a resumed session (one round trip less on reconnect).
	// Opt-in because early data is replayable.
	ZeroRTT bool
	// MTU is the QUIC Initial packet size (path MTU budget) from ?mtu=1452.
	// Zero keeps the safe default (1280), which fits every path; set it only
	// when the path is known to carry 1500-byte datagrams.
	MTU int
}

// NewMasque builds a Masque from a link.
func NewMasque(link string) (dialer.Dialer, *dialer.Property, error) {
	if !strings.HasPrefix(link, "masque://") {
		return nil, nil, dialer.InvalidParameterErr
	}
	s, err := parseMasqueURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s, &dialer.Property{
		Name:     s.Name,
		Protocol: "masque",
		Address:  s.Host,
		Link:     s.link,
	}, nil
}

func parseMasqueURL(link string) (*Masque, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, dialer.InvalidParameterErr
	}
	sni := u.Query().Get("peer")
	if sni == "" {
		sni = u.Query().Get("sni")
	}
	name := u.Fragment
	if name == "" {
		name = "masque"
	}
	return &Masque{
		link:     link,
		Name:     name,
		Host:     u.Host,
		Sni:      sni,
		Insecure: u.Query().Get("insecure") == "1",
		QuicV2:   quicV2Requested(u.Query()),
		ZeroRTT:  protocol.ZeroRTTRequested(u.Query()),
		MTU:      mtuRequested(u.Query()),
	}, nil
}

// mtuRequested parses ?mtu=1452 into an Initial packet size, ignoring values
// quic-go would refuse to use (it clamps to [1200, 65535] anyway, but a silent
// clamp would make the link parameter look effective when it is not).
func mtuRequested(q url.Values) int {
	v := q.Get("mtu")
	if v == "" {
		return 0
	}
	mtu, err := strconv.Atoi(v)
	if err != nil || mtu < 1200 || mtu > 65535 {
		return 0
	}
	return mtu
}

// quicV2Requested reports whether the link asks for QUIC v2 first.
func quicV2Requested(q url.Values) bool {
	v := q.Get("quic_version")
	if v == "" {
		v = q.Get("quic-version")
	}
	return v == "2" || v == "v2" || q.Get("quicv2") == "1"
}

// Dialer builds the runtime dialer, optionally layered on parent.
func (s *Masque) Dialer(option *dialer.ExtraOption, parentDialer netproxy.Dialer) (netproxy.Dialer, error) {
	insecure := s.Insecure
	if option != nil && option.AllowInsecure {
		insecure = true
	}
	return NewDialer(parentDialer, s.Host, s.Sni, insecure, s.QuicV2, s.ZeroRTT, s.MTU)
}
