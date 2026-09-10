package masque

import (
	"net/url"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
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
	}, nil
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
	return NewDialer(parentDialer, s.Host, s.Sni, insecure, s.QuicV2)
}
