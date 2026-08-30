package client

import (
	"net"

	C "github.com/daeuniverse/outbound/common"
)

// addrsCache aliases the shared refreshable candidate cache (common.AddrCache):
// re-resolves when the list is stale or the previous connect failed, and falls
// back to the cached list when re-resolution fails. See common/addr_cache.go
// for the refresh rules.
type addrsCache = C.AddrCache

func newAddrsCache(seed []net.Addr, resolve func() ([]net.Addr, error)) *addrsCache {
	return C.NewAddrCache(seed, resolve)
}
