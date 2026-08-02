package common

import (
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
	"github.com/daeuniverse/quic-go"
)

const (
	InitialStreamReceiveWindow     = 8 * 1024 * 1024  // 8 MB (fast start — netem sweep confirmed)
	MaxStreamReceiveWindow         = 32 * 1024 * 1024 // 32 MB
	InitialConnectionReceiveWindow = 12 * 1024 * 1024 // 12 MB (reduced from 32MB; enough for 1-2 concurrent streams)
	MaxConnectionReceiveWindow     = 64 * 1024 * 1024 // 64 MB
)

func SetCongestionController(quicConn quic.Connection, cc string, cwnd int) {
	switch cc {
	default:
		fallthrough
	case "bbr":
		congestion.UseBBR(quicConn)
	}
}
