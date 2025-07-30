package protocol

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/daeuniverse/outbound/netproxy"
)

type Creator func(nextDialer netproxy.Dialer, header Header) (netproxy.Dialer, error)

var Mapper = make(map[string]Creator)

func Register(name string, c Creator) {
	Mapper[name] = c
}

func NewDialer(name string, nextDialer netproxy.Dialer, header Header) (netproxy.Dialer, error) {
	creator, ok := Mapper[name]
	if !ok {
		return nil, fmt.Errorf("no conn creator registered for %v", strconv.Quote(name))
	}
	return creator(nextDialer, header)
}

type BasicDialer struct {
	Dial            func(c net.Conn, network, addr string) (net.Conn, error)
	DialNextContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d BasicDialer) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	c, err := d.DialNextContext(ctx, network, addr)
	if err != nil {
		return
	}
	dialCh := make(chan struct{})
	go func() {
		conn, err = d.Dial(c, network, addr)
		dialCh <- struct{}{}
	}()
	select {
	case <-dialCh:
		return
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	}
}
