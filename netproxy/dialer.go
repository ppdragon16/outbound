package netproxy

import (
	"context"
	"net"
	"time"
)

var (
	DialTimeout = 8 * time.Second
)

func NewDialTimeoutContextFrom(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DialTimeout)
}

func NewDialTimeoutContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DialTimeout)
}

// A Dialer is a means to establish a connection.
// Must return while the context is cancelled. Otherwise, everything will be blocked.
// ListenPacket may not be fullcone for some protocols. For fullcone protocols, address will be ignored.
// 对于 FullCone 协议，ListenPacket 意味着在目标 dialer 上分配 lAddr, 并在收到数据包时回复
type Dialer interface {
	Alive() bool
	Connect() error
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket(ctx context.Context, address string) (net.PacketConn, error)
}
