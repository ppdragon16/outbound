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

// SetCongestionController wires the configured congestion controller into the
// QUIC connection. "brutal" uses cwnd as the target bandwidth in bytes per
// second (community convention shared with sing-box and the tuic brutal
// forks); when it is zero the connection falls back to BBR.
func SetCongestionController(quicConn quic.Connection, cc string, cwnd uint64) {
	switch cc {
	case "brutal":
		if cwnd == 0 {
			congestion.UseBBR(quicConn)
			return
		}
		congestion.UseBrutal(quicConn, cwnd)
	default:
		congestion.UseBBR(quicConn)
	}
}
