package netproxy

type ProxyAddr struct {
	network string
	address string // can be domain:port or ip:port
}

func NewProxyAddr(network, address string) *ProxyAddr {
	return &ProxyAddr{network, address}
}

func (a *ProxyAddr) Network() string { return a.network }
func (a *ProxyAddr) String() string  { return a.address }
