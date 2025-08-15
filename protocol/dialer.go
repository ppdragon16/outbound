package protocol

import (
	"fmt"
	"strconv"

	"github.com/daeuniverse/outbound/netproxy"
)

type Creator func(parentDialer netproxy.Dialer, header Header) (netproxy.Dialer, error)

var Mapper = make(map[string]Creator)

func Register(name string, c Creator) {
	Mapper[name] = c
}

func NewDialer(name string, parentDialer netproxy.Dialer, header Header) (netproxy.Dialer, error) {
	creator, ok := Mapper[name]
	if !ok {
		return nil, fmt.Errorf("no conn creator registered for %v", strconv.Quote(name))
	}
	return creator(parentDialer, header)
}

type StatelessDialer struct {
	ParentDialer netproxy.Dialer
}

func (d *StatelessDialer) Connect() (err error) {
	return d.ParentDialer.Connect()
}

func (d *StatelessDialer) Alive() bool {
	return d.ParentDialer.Alive()
}
