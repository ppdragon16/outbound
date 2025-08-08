package dialer

import (
	"fmt"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type ExtraOption struct {
	AllowInsecure       bool
	TlsImplementation   string
	TlsFragment         bool
	TlsFragmentLength   string
	TlsFragmentInterval string
	UtlsImitate         string
	BandwidthMaxTx      string
	BandwidthMaxRx      string
	UDPHopInterval      time.Duration
}

type Property struct {
	Name     string
	Address  string
	Protocol string
	Link     string
}

type Dialer interface {
	Dialer(option *ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, error)
}
