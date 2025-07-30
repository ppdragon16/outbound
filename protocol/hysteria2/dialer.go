package hysteria2

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/client"
	"github.com/daeuniverse/outbound/protocol/hysteria2/udphop"
	"github.com/samber/oops"
)

func init() {
	protocol.Register("hysteria2", NewDialer)
}

// Why Metadata?
type Dialer struct {
	client   *client.Client
	metadata protocol.Metadata
}

type Feature1 struct {
	BandwidthConfig client.BandwidthConfig
	UDPHopInterval  time.Duration
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	host, port := parseServerAddrString(header.ProxyAddress)
	config := &client.Config{
		TLSConfig: client.TLSConfig{
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
		client: client,
		metadata: protocol.Metadata{
			IsClient: header.IsClient,
		},
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

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := d.client.PrepareConn(ctx); err != nil {
		return nil, err
	}
	switch network {
	case "tcp":
		stream, err := d.client.OpenStream(ctx)
		if err != nil {
			return nil, err
		}
		return common.Invoke(ctx, func() (net.Conn, error) {
			return d.client.DialConn(stream, address)
		}, func() {
			stream.Close()
		})
	case "udp":
		c, err := d.client.ListenPacket()
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: c,
			Address:    netproxy.NewProxyAddr("udp", address),
		}, nil
	default:
		return nil, oops.Errorf("unsupported network: %s", network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, _ string) (net.PacketConn, error) {
	if err := d.client.PrepareConn(ctx); err != nil {
		return nil, err
	}
	return d.client.ListenPacket()
}
