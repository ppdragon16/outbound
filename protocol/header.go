package protocol

import utls "github.com/refraction-networking/utls"

type Header struct {
	ProxyAddress string
	SNI          string
	Feature1     interface{}
	TlsConfig    *utls.Config
	Cipher       string
	User         string
	Password     string
	Flags        Flags
}

type Flags uint64

const (
	Flags_VMess_UsePacketAddr = 1 << iota
	Flags_VLess_TcpMux
)

const (
	Flags_Tuic_UdpRelayModeQuic = 1 << iota
)
