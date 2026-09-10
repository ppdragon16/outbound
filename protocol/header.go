package protocol

import utls "github.com/refraction-networking/utls"

type Header struct {
	ProxyAddress string
	SNI          string
	Feature1     any
	Feature2     any
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

// Flags_Quic_PreferV2 asks QUIC-based outbounds (tuic, juicity, masque) to
// offer QUIC v2 (RFC 9369) in their first packet, keeping v1 in the version
// list for negotiation fallback. Without it the QUIC stack keeps its default
// order (v1 first), so the 0x00000001 wire pattern stays untouched.
//
// The value is explicit because the iota groups above reuse the same bit space.
const Flags_Quic_PreferV2 Flags = 1 << 8
