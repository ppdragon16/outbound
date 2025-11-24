package anytls

import (
	"crypto/tls"
	"net/url"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	dialer.FromLinkRegister("anytls", NewAnytls)
}

type Anytls struct {
	link     string
	Name     string
	Auth     string
	Host     string
	Sni      string
	Insecure bool
}

func NewAnytls(link string) (dialer.Dialer, *dialer.Property, error) {
	switch {
	case strings.HasPrefix(link, "anytls://"):
		s, err := parseAnytlsURL(link)
		if err != nil {
			return nil, nil, err
		}
		return s, &dialer.Property{
			Name:     s.Name,
			Protocol: "anytls",
			Address:  s.Host,
			Link:     s.link,
		}, nil
	default:
		return nil, nil, dialer.InvalidParameterErr
	}
}

func parseAnytlsURL(link string) (*Anytls, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	sni := u.Query().Get("peer")
	if len(sni) == 0 {
		sni = u.Query().Get("sni")
	}
	if len(sni) == 0 {
		// disable the SNI
		sni = "127.0.0.1"
	}
	name := u.Fragment
	if len(name) == 0 {
		name = "anytls"
	}
	antls := &Anytls{
		link:     link,
		Name:     name,
		Auth:     u.User.Username(),
		Host:     u.Host,
		Sni:      sni,
		Insecure: u.Query().Get("insecure") == "1",
	}

	return antls, nil
}

func (s *Anytls) Dialer(option *dialer.ExtraOption, parentDialer netproxy.Dialer) (netproxy.Dialer, error) {
	return protocol.NewDialer(
		"anytls",
		parentDialer,
		protocol.Header{
			ProxyAddress: s.Host,
			Password:     s.Auth,
			TlsConfig: &tls.Config{
				ServerName:         s.Sni,
				InsecureSkipVerify: s.Insecure,
			},
		})
}
