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

// UseBBRV3 swaps the connection onto BBRv3 (draft-ietf-ccwg-bbr-06).
// Opt-in only: callers must pass congestion_control=bbrv3 explicitly.
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
// tuic/common.SetCongestionController; "brutal" falls back to BBR here
// because the negotiated bandwidth isn't known yet.
func NewInitialSender(name string, addr net.Addr) quiccongestion.CongestionControl {
	switch name {
	case "bbrv3":
		return bbrv3.NewBbr3Sender(bbrv3.DefaultClock{}, bbrv3.GetInitialPacketSize(addr))
	default:
		return bbr.NewBbrSender(bbr.DefaultClock{}, bbr.GetInitialPacketSize(addr))
	}
}
