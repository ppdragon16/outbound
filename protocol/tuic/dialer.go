package tuic

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
	"github.com/google/uuid"

	C "github.com/daeuniverse/outbound/common"
)

func init() {
	protocol.Register("tuic", NewDialer)
}

type Dialer struct {
	clientRing *clientRing

	proxyAddress string
	nextDialer   netproxy.Dialer
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	id, err := uuid.Parse(header.User)
	if err != nil {
		return nil, fmt.Errorf("parse UUID: %w", err)
	}
	// ensure server's incoming stream can handle correctly, increase to 1.1x
	maxDatagramFrameSize := 1400
	udpRelayMode := common.NATIVE
	if header.Flags&protocol.Flags_Tuic_UdpRelayModeQuic > 0 {
		// FIXME: QUIC has severe performance problems.
		// udpRelayMode = common.QUIC
	}
	return &Dialer{
		clientRing: newClientRing(func(capabilityCallback func(n int64)) *clientImpl {
			return &clientImpl{
				ClientOption: &ClientOption{
					TlsConfig: header.TlsConfig,
					QuicConfig: &quic.Config{
						InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
						MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
						InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
						MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
						KeepAlivePeriod:                3 * time.Second,
						DisablePathMTUDiscovery:        false,
						EnableDatagrams:                true,
						HandshakeIdleTimeout:           8 * time.Second,
						CapabilityCallback:             capabilityCallback,
					},
					Uuid:                  id,
					Password:              header.Password,
					UdpRelayMode:          udpRelayMode,
					CongestionController:  header.Feature1.(string),
					ReduceRtt:             false,
					CWND:                  10,
					MaxUdpRelayPacketSize: maxDatagramFrameSize,
				},
				udp: true,
			}
		}, 10),
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
	}, nil
}

func (d *Dialer) dialFuncFactory(rAddr net.Addr) common.DialFunc {
	return func(ctx context.Context, dialer netproxy.Dialer) (transport *quic.Transport, addr net.Addr, err error) {
		pc, err := dialer.ListenPacket(ctx, d.proxyAddress)
		if err != nil {
			return nil, nil, err
		}
		transport = &quic.Transport{Conn: pc}
		return transport, rAddr, nil
	}
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = true
		proxyAddr, err := C.ResolveUDPAddr(d.proxyAddress)
		if err != nil {
			return nil, err
		}
		if network == "tcp" {
			tcpConn, err := d.clientRing.DialContextWithDialer(ctx, &mdata, d.nextDialer,
				d.dialFuncFactory(proxyAddr),
			)
			if err != nil {
				return nil, err
			}
			return tcpConn, nil
		} else {
			udpConn, err := d.clientRing.ListenPacketWithDialer(ctx, &mdata, d.nextDialer,
				d.dialFuncFactory(proxyAddr),
			)
			if err != nil {
				return nil, err
			}
			return &netproxy.BindPacketConn{
				PacketConn: udpConn,
				Address:    netproxy.NewAddr("udp", addr),
			}, nil
		}

	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return nil, err
	}
	mdata.IsClient = true
	proxyAddr, err := C.ResolveUDPAddr(d.proxyAddress)
	if err != nil {
		return nil, err
	}
	return d.clientRing.ListenPacketWithDialer(ctx, &mdata, d.nextDialer,
		d.dialFuncFactory(proxyAddr),
	)
}

// Connect implements netproxy.Dialer.
func (d *Dialer) Connect() error {
	return d.nextDialer.Connect()
}

// Disconnect implements netproxy.Dialer.
func (d *Dialer) Disconnect() error {
	return d.nextDialer.Disconnect()
}

// Alive implements netproxy.Dialer.
func (d *Dialer) Alive() bool {
	return d.nextDialer.Alive()
}
