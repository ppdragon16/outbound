package hysteria2

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/client"
	"github.com/daeuniverse/outbound/protocol/hysteria2/udphop"
)

func init() {
	protocol.Register("hysteria2", NewDialer)
}

// Why Metadata?
type Dialer struct {
	*client.Client
}

type Feature1 struct {
	BandwidthConfig client.BandwidthConfig
	UDPHopInterval  time.Duration
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	host, port := parseServerAddrString(header.ProxyAddress)
	config := &client.Config{
		TLSConfig: tls.Config{
			ServerName:            header.TlsConfig.ServerName,
			InsecureSkipVerify:    header.TlsConfig.InsecureSkipVerify,
			VerifyPeerCertificate: header.TlsConfig.VerifyPeerCertificate,
			RootCAs:               header.TlsConfig.RootCAs,
		},
		Auth:       header.User,
		FastOpen:   true,
		NextDialer: nextDialer,
	}

	if header.SNI == "" {
		config.TLSConfig.ServerName = host
	}
	if header.Password != "" {
		config.Auth = header.User + ":" + header.Password
	}
	if feature := header.Feature1; feature != nil {
		config.BandwidthConfig = feature.(*Feature1).BandwidthConfig
		config.UDPHopInterval = feature.(*Feature1).UDPHopInterval
	}

	var err error
	if isPortHoppingPort(port) {
		config.Addr, err = udphop.ResolveUDPHopAddr(net.JoinHostPort(host, port))
	} else {
		config.Addr, err = common.ResolveUDPAddr(net.JoinHostPort(host, port))
	}
	if err != nil {
		return nil, err
	}

	client, err := client.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &Dialer{
		Client: client,
	}, nil
}

// parseServerAddrString parses server address string.
// Server address can be in either "host:port" or "host" format (in which case we assume port 443).
func parseServerAddrString(addrStr string) (host, port string) {
	h, p, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr, "443"
	}
	return h, p
}

// isPortHoppingPort returns whether the port string is a port hopping port.
// We consider a port string to be a port hopping port if it contains "-" or ",".
func isPortHoppingPort(port string) bool {
	return strings.Contains(port, "-") || strings.Contains(port, ",")
}
