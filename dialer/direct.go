package dialer

import (
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func NewDirectDialer(option *ExtraOption) (netproxy.Dialer, *Property) {
	property := &Property{
		Name:     "direct",
		Address:  "",
		Protocol: "",
		Link:     "",
	}
	return direct.Direct, property
}
