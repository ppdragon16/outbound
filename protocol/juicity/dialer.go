package juicity

import (
	"context"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"

	C "github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
	"github.com/google/uuid"
)

func init() {
	protocol.Register("juicity", NewDialer)
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
	maxOpenIncomingStreams := int64(100)
	quicMaxOpenIncomingStreams := int64(maxOpenIncomingStreams)
	quicMaxOpenIncomingStreams = quicMaxOpenIncomingStreams + int64(math.Ceil(float64(quicMaxOpenIncomingStreams)/10.0))
	reservedStreamsCapability := maxOpenIncomingStreams / 5
	if reservedStreamsCapability < 1 {
		reservedStreamsCapability = 1
	}
	if reservedStreamsCapability > 5 {
		reservedStreamsCapability = 5
	}
	return &Dialer{
		clientRing: newClientRing(func(capabilityCallback func(n int64)) *clientImpl {
			ctx, cancel := context.WithCancel(context.Background())
			return &clientImpl{
				ClientOption: &ClientOption{
					TlsConfig: header.TlsConfig,
					QuicConfig: &quic.Config{
						InitialStreamReceiveWindow:     common.InitialStreamReceiveWindow,
						MaxStreamReceiveWindow:         common.MaxStreamReceiveWindow,
						InitialConnectionReceiveWindow: common.InitialConnectionReceiveWindow,
						MaxConnectionReceiveWindow:     common.MaxConnectionReceiveWindow,
						KeepAlivePeriod:                5 * time.Second,
						DisablePathMTUDiscovery:        false,
						EnableDatagrams:                false,
						HandshakeIdleTimeout:           8 * time.Second,
						CapabilityCallback:             capabilityCallback,
					},
					Uuid:                 id,
					Password:             header.Password,
					CongestionController: header.Feature1.(string),
					CWND:                 10,
					Ctx:                  ctx,
					Cancel:               cancel,
					UnderlayAuth:         make(chan *UnderlayAuth, 64),
				},
			}
		}, reservedStreamsCapability),
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

// DialContext implements netproxy.Dialer.
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
		if network == "udp" {
			switch mdata.Port {
			case 0:
				iv, psk, err := d.clientRing.DialAuth(ctx, &Metadata{
					Metadata: mdata,
					Network:  network,
				}, d.nextDialer, d.dialFuncFactory(proxyAddr))
				if err != nil {
					return nil, err
				}
				innerAddr, err := C.ResolveUDPAddr(net.JoinHostPort(mdata.Hostname, strconv.Itoa(int(mdata.Port))))
				if err != nil {
					return nil, err
				}
				transport, _, err := d.dialFuncFactory(proxyAddr)(context.TODO(), d.nextDialer)
				if err != nil {
					return nil, err
				}
				pktConn := &TransportPacketConn{
					Transport: transport,
					proxyAddr: proxyAddr,
					tgt:       innerAddr.AddrPort(),
					masterKey: psk,
					firstIv:   iv,
				}
				return &netproxy.BindPacketConn{
					PacketConn: pktConn,
					Address:    netproxy.NewAddr("udp", addr),
				}, nil
			}
		}
		conn, err := d.clientRing.DialContext(ctx, &Metadata{
			Metadata: mdata,
			Network:  network,
		}, d.nextDialer,
			d.dialFuncFactory(proxyAddr),
		)
		if err != nil {
			return nil, err
		}
		if network == "tcp" {
			time.AfterFunc(100*time.Millisecond, func() {
				// avoid the situation where the server sends messages first
				if _, err = conn.Write(nil); err != nil {
					return
				}
			})
			return conn, nil
		} else {
			// UDP packet conn wrapping a QUIC stream
			return &netproxy.BindPacketConn{
				PacketConn: &PacketConn{Conn: conn},
				Address:    netproxy.NewAddr("udp", addr),
			}, nil
		}

	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

// ListenPacket implements netproxy.Dialer.
func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	// For juicity, we use a QUIC stream as the UDP transport.
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return nil, err
	}
	mdata.IsClient = true
	proxyAddr, err := C.ResolveUDPAddr(d.proxyAddress)
	if err != nil {
		return nil, err
	}
	conn, err := d.clientRing.DialContext(ctx, &Metadata{
		Metadata: mdata,
		Network:  "udp",
	}, d.nextDialer,
		d.dialFuncFactory(proxyAddr),
	)
	if err != nil {
		return nil, err
	}
	return &PacketConn{Conn: conn}, nil
}

func (d *Dialer) DialCmdMsg(ctx context.Context, cmd protocol.MetadataCmd) (c net.Conn, err error) {
	proxyAddr, err := C.ResolveUDPAddr(d.proxyAddress)
	if err != nil {
		return nil, err
	}
	conn, err := d.clientRing.DialContext(ctx, &Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeMsg,
			Cmd:      cmd,
			IsClient: true,
		},
	}, d.nextDialer,
		d.dialFuncFactory(proxyAddr),
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
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
