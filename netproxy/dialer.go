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
// 对于 FullCone 协议，ListenPacket 通常不会在目标 dialer 上分配 lAddr, 通常是在 writeTo 时分配
// 这些协议一般依赖于id等字段来区分返回的数据包属于哪个连接, 因为lAddr通常不会包括在报文内
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket(ctx context.Context, address string) (net.PacketConn, error)
}
