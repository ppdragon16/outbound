package vmess

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/google/uuid"
)

func init() {
	protocol.Register("vmess", NewDialer)
	protocol.Register("vmess+tls+grpc", NewDialer)
}

type Dialer struct {
	protocol.StatelessDialer
	proxyAddress      string
	nextDialer        netproxy.Dialer
	metadata          protocol.Metadata
	key               []byte
	featurePacketAddr bool
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: true,
	}
	cipher, _ := ParseCipherFromSecurity(Cipher(header.Cipher).ToSecurity())
	metadata.Cipher = string(cipher)

	// UUID mapping
	password := header.Password
	if l := len([]byte(password)); l < 32 || l > 36 {
		password = common.StringToUUID5(password)
	}

	id, err := uuid.Parse(password)
	if err != nil {
		return nil, err
	}

	return &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: nextDialer,
		},
		proxyAddress:      header.ProxyAddress,
		nextDialer:        nextDialer,
		metadata:          metadata,
		key:               NewID(id).CmdKey(),
		featurePacketAddr: header.Flags&protocol.Flags_VMess_UsePacketAddr > 0,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.Cipher = d.metadata.Cipher
		mdata.IsClient = d.metadata.IsClient
		if d.featurePacketAddr && network == "udp" {
			mdata.Hostname = SeqPacketMagicAddress
			mdata.Type = protocol.MetadataTypeDomain
		}

		conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
		if err != nil {
			return nil, err
		}

		vConn, err := NewConn(conn, Metadata{
			Metadata: mdata,
			Network:  network,
		}, addr, d.key)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return vConn, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return nil, err
	}
	mdata.Cipher = d.metadata.Cipher
	mdata.IsClient = d.metadata.IsClient
	if d.featurePacketAddr {
		mdata.Hostname = SeqPacketMagicAddress
		mdata.Type = protocol.MetadataTypeDomain
	}

	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	vConn, err := NewConn(conn, Metadata{
		Metadata: mdata,
		Network:  "udp",
	}, addr, d.key)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return vConn, nil
}
