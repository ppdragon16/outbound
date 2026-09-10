package juicity

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	dialer.FromLinkRegister("juicity", NewJuicity)
}

type Juicity struct {
	Name                  string
	Server                string
	Port                  int
	User                  string
	Password              string
	Sni                   string
	AllowInsecure         bool
	CongestionControl     string
	PinnedCertchainSha256 string
	// QuicV2 offers QUIC v2 (RFC 9369) in the first packet.
	QuicV2   bool
	Protocol string
}

func NewJuicity(link string) (dialer.Dialer, *dialer.Property, error) {
	s, err := ParseJuicityURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s, &dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}, nil
}

func (s *Juicity) Dialer(option *dialer.ExtraOption, parentDialer netproxy.Dialer) (netproxy.Dialer, error) {
	d := parentDialer
	var err error
	tlsConfig := &utls.Config{
		NextProtos:         []string{"h3"},
		MinVersion:         utls.VersionTLS13,
		ServerName:         s.Sni,
		InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure,
	}
	if s.PinnedCertchainSha256 != "" {
		pinnedHash, err := base64.URLEncoding.DecodeString(s.PinnedCertchainSha256)
		if err != nil {
			pinnedHash, err = base64.StdEncoding.DecodeString(s.PinnedCertchainSha256)
			if err != nil {
				pinnedHash, err = hex.DecodeString(s.PinnedCertchainSha256)
				if err != nil {
					return nil, fmt.Errorf("failed to decode PinnedCertchainSha256")
				}
			}
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if !bytes.Equal(common.GenerateCertChainHash(rawCerts), pinnedHash) {
				return fmt.Errorf("pinned hash of cert chain does not match")
			}
			return nil
		}
	}
	var flags protocol.Flags
	if s.QuicV2 {
		flags |= protocol.Flags_Quic_PreferV2
	}
	if d, err = protocol.NewDialer("juicity", d, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Feature1:     s.CongestionControl,
		TlsConfig:    tlsConfig,
		User:         s.User,
		Password:     s.Password,
		Flags:        flags,
	}); err != nil {
		return nil, err
	}
	return d, nil
}

// QuicV2Requested reports whether a link asks for QUIC v2 (RFC 9369) in the
// first packet via ?quic_version=2 (or the quicv2=1 alias).
func QuicV2Requested(q url.Values) bool {
	v := q.Get("quic_version")
	if v == "" {
		v = q.Get("quic-version")
	}
	return v == "2" || v == "v2" || q.Get("quicv2") == "1"
}

func ParseJuicityURL(u string) (data *Juicity, err error) {
	t, err := url.Parse(u)
	if err != nil {
		err = fmt.Errorf("invalid juicity format")
		return
	}
	allowInsecure, _ := strconv.ParseBool(t.Query().Get("allowInsecure"))
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(t.Query().Get("allow_insecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(t.Query().Get("allowinsecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(t.Query().Get("skipVerify"))
	}
	sni := t.Query().Get("peer")
	if sni == "" {
		sni = t.Query().Get("sni")
	}
	if sni == "" {
		sni = t.Hostname()
	}
	port, err := strconv.Atoi(t.Port())
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	password, _ := t.User.Password()
	data = &Juicity{
		Name:                  t.Fragment,
		Server:                t.Hostname(),
		Port:                  port,
		User:                  t.User.Username(),
		Password:              password,
		Sni:                   sni,
		AllowInsecure:         allowInsecure,
		CongestionControl:     t.Query().Get("congestion_control"),
		QuicV2:                QuicV2Requested(t.Query()),
		PinnedCertchainSha256: t.Query().Get("pinned_certchain_sha256"),
		Protocol:              "juicity",
	}
	return data, nil
}

func (t *Juicity) ExportToURL() string {
	u := &url.URL{
		Scheme:   "juicity",
		User:     url.UserPassword(t.User, t.Password),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		Fragment: t.Name,
	}
	q := u.Query()
	if t.AllowInsecure {
		q.Set("allow_insecure", "1")
	}
	common.SetValue(&q, "sni", t.Sni)
	common.SetValue(&q, "congestion_control", t.CongestionControl)
	common.SetValue(&q, "pinned_certchain_sha256", t.PinnedCertchainSha256)
	if t.QuicV2 {
		common.SetValue(&q, "quic_version", "2")
	}
	u.RawQuery = q.Encode()
	return u.String()
}
