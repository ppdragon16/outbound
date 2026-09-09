package congestion

import (
	"net"

	"github.com/daeuniverse/outbound/protocol/tuic/congestion/bbr"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion/bbrv3"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion/brutal"
	"github.com/daeuniverse/quic-go"
	quiccongestion "github.com/daeuniverse/quic-go/congestion"
)

func UseBBR(conn quic.Connection) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

// UseBBRV3 installs the BBRv3 (draft-ietf-ccwg-bbr-06) sender. It is the
// default congestion controller on QUIC-based protocols (tuic, juicity,
// hysteria2); pass congestion_control=bbr to restore the BBRv1 default.
func UseBBRV3(conn quic.Connection) {
	conn.SetCongestionControl(bbrv3.NewBbr3Sender(
		bbrv3.DefaultClock{},
		bbrv3.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

func UseBrutal(conn quic.Connection, tx uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx))
}

// NewInitialSender returns the initial congestion-control sender for the
// named controller, so connections that would immediately swap CC don't pay
// for a throwaway CUBIC sender. Mirrors the names accepted by
// tuic/common.SetCongestionController (default = BBRv3); "brutal" falls back
// to BBRv3 here because the negotiated bandwidth isn't known yet, and "bbr"
// restores the BBRv1 default.
func NewInitialSender(name string, addr net.Addr) quiccongestion.CongestionControl {
	switch name {
	case "bbr":
		return bbr.NewBbrSender(bbr.DefaultClock{}, bbr.GetInitialPacketSize(addr))
	default:
		return bbrv3.NewBbr3Sender(bbrv3.DefaultClock{}, bbrv3.GetInitialPacketSize(addr))
	}
}
