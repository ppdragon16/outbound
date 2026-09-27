package protocol

import (
	"sync"

	utls "github.com/refraction-networking/utls"
)

// zeroRTTCacheCapacity is the number of resumable TLS sessions retained
// process-wide. One entry per (server name, ALPN) is enough for a handful of
// nodes; the LRU evicts the rest.
const zeroRTTCacheCapacity = 64

var (
	zeroRTTCacheOnce sync.Once
	zeroRTTCache     utls.ClientSessionCache
)

// ZeroRTTSessionCache returns the process-wide TLS session cache used by the
// protocols whose first request can travel in QUIC 0-RTT (masque today).
//
// A cache is the prerequisite for 0-RTT: without one the client never resumes,
// so quic.DialEarly's early-connection channel never fires and DialEarly
// behaves exactly like Dial. The cache is shared so that every node reuses the
// tickets the server issued, keyed internally by server name and ALPN.
//
// Callers must only install it when their first request tolerates early data:
// tuic and juicity cannot (their v5 token is the exporter of the *completed*
// handshake, which is why tuic clears ClientSessionCache outright), and
// hysteria2 cannot either (its auth request is an HTTP/3 POST, which the H3
// client only sends after the handshake, and no hysteria2 server accepts
// 0-RTT).
func ZeroRTTSessionCache() utls.ClientSessionCache {
	zeroRTTCacheOnce.Do(func() {
		zeroRTTCache = utls.NewLRUClientSessionCache(zeroRTTCacheCapacity)
	})
	return zeroRTTCache
}

// queryValues is the subset of url.Values this package needs. Both net/url and
// the port-hopping fork used by the link parsers satisfy it, so the helper does
// not force either representation on its callers.
type queryValues interface {
	Get(string) string
}

// ZeroRTTRequested reports whether a link's query opts into 0-RTT. 0-RTT data
// is replayable by an observer, so it stays opt-in per outbound rather than
// being switched on globally.
func ZeroRTTRequested(q queryValues) bool {
	for _, key := range []string{"zero_rtt", "zero-rtt", "zerortt", "0rtt", "reduce_rtt"} {
		if v := q.Get(key); v == "1" || v == "true" {
			return true
		}
	}
	return false
}
