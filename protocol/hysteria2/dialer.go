package hysteria2

import (
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/client"
	"github.com/daeuniverse/outbound/protocol/hysteria2/udphop"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
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
	ObfsPassword    string
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	host, port := parseServerAddrString(header.ProxyAddress)
	config := &client.Config{
		TLSConfig: utls.Config{
			ServerName:            header.TlsConfig.ServerName,
			InsecureSkipVerify:    header.TlsConfig.InsecureSkipVerify,
			VerifyPeerCertificate: header.TlsConfig.VerifyPeerCertificate,
			RootCAs:               header.TlsConfig.RootCAs,
		},
		Auth:       header.User,
		FastOpen:   true,
		NextDialer: nextDialer,
	}
	// hysteria2's auth round trip is HTTP/3, and quic-go's http3 dialer refuses
	// multi-version configs, so preferring v2 pins it (no v1 fallback).
	config.QUICConfig.Versions = protocol.QuicVersionsHTTP3(header.Flags)

	if header.SNI == "" {
		config.TLSConfig.ServerName = host
	}
	if header.Password != "" {
		config.Auth = header.User + ":" + header.Password
	}
	if feature := header.Feature1; feature != nil {
		config.BandwidthConfig = feature.(*Feature1).BandwidthConfig
		config.UDPHopInterval = feature.(*Feature1).UDPHopInterval
		config.ObfsPassword = feature.(*Feature1).ObfsPassword
	}

	serverAddr := net.JoinHostPort(host, port)
	portHopping := isPortHoppingPort(port)
	var err error
	if portHopping {
		config.Addrs, err = udphop.ResolveUDPHopAddrs(serverAddr)
	} else {
		config.Addrs, err = common.ResolveUDPAddrs(serverAddr)
	}
	if err != nil {
		return nil, err
	}
	// Let the client refresh the candidate list on later connects instead of
	// dialing this build-time snapshot forever: providers rotate entry IPs
	// and a dead address family (e.g. flaky v6) must heal on the next connect
	// without a daemon restart.
	config.ServerAddr = serverAddr
	config.PortHopping = portHopping

	// Install the default congestion controller (BBRv3) at dial time. The
	// previous flow let the connection start with a throwaway CUBIC sender
	// and then swapped controllers after the handshake, while the receive
	// path was live (a data race, plus a few RTTs on the wrong controller).
	// brutal - bandwidth pinned by the server's auth response - is the only
	// controller still installed after the handshake.
	config.QUICConfig.InitialCongestionControl = congestion.NewInitialSender("", ccPacketSizeAddr(host))

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

// ccPacketSizeAddr gives a congestion controller an address to derive its
// initial packet size from: an IP literal keeps its address family, while a
// hostname yields nil, which the helper treats as the conservative minimum.
func ccPacketSizeAddr(host string) net.Addr {
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip}
	}
	return nil
}
