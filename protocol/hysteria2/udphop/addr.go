package udphop

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/common"
)

type InvalidPortError struct {
	PortStr string
}

func (e InvalidPortError) Error() string {
	return fmt.Sprintf("%s is not a valid port number or range", e.PortStr)
}

// UDPHopAddr contains an IP address and a compact list of port ranges.
// Ranges are kept in normalized form ([Start, End] inclusive, non-overlapping,
// sorted) so memory cost is O(ranges), not O(ports). For a single
// "60000-65530" range that's 4 bytes (one PortRange) instead of ~11 KiB
// (5531 uint16 entries).
type UDPHopAddr struct {
	IP      net.IP
	Ranges  PortUnion
	PortStr string
}

func (a *UDPHopAddr) Network() string {
	return "udphop"
}

func (a *UDPHopAddr) String() string {
	return net.JoinHostPort(a.IP.String(), a.PortStr)
}

// TotalPorts returns the number of ports covered by all ranges.
func (a *UDPHopAddr) TotalPorts() int {
	total := 0
	for _, r := range a.Ranges {
		total += int(r.End) - int(r.Start) + 1
	}
	return total
}

// PickRandomAddr returns a uniformly-random *net.UDPAddr drawn from all
// port ranges on this address's IP. Each port maps to exactly one offset
// in [0, TotalPorts()), so the distribution is uniform.
func (a *UDPHopAddr) PickRandomAddr() *net.UDPAddr {
	total := a.TotalPorts()
	if total == 0 {
		return nil
	}
	target := rand.Intn(total)
	var port uint16
	for _, r := range a.Ranges {
		size := int(r.End) - int(r.Start) + 1
		if target < size {
			port = r.Start + uint16(target)
			break
		}
		target -= size
	}
	return &net.UDPAddr{
		IP:   a.IP,
		Port: int(port),
	}
}

func ResolveUDPHopAddr(addr string) (*UDPHopAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := common.ResolveIPAddr(host)
	if err != nil {
		return nil, err
	}

	pu := ParsePortUnion(portStr)
	if pu == nil {
		return nil, InvalidPortError{portStr}
	}
	// Store the compact ranges directly — no need to expand to []uint16
	// here. UDPHopAddr.PickRandomAddr works on the ranges.
	return &UDPHopAddr{
		IP:      ip.IP,
		Ranges:  pu,
		PortStr: portStr,
	}, nil
}

// ResolveUDPHopAddrs resolves addr (host:port-range) to all of its IPs as
// UDPHopAddr candidates, sorted IPv4-first. Used for happy-eyeballs racing of
// a port-hopping dialer: each candidate races its own random-port handshake.
func ResolveUDPHopAddrs(addr string) ([]net.Addr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := common.ResolveIPAddrs(host)
	if err != nil {
		return nil, err
	}

	pu := ParsePortUnion(portStr)
	if pu == nil {
		return nil, InvalidPortError{portStr}
	}
	out := make([]net.Addr, 0, len(ips))
	for i := range ips {
		out = append(out, &UDPHopAddr{
			IP:      ips[i].IP,
			Ranges:  pu,
			PortStr: portStr,
		})
	}
	return out, nil
}

// PortUnion is a collection of multiple port ranges.
type PortUnion []PortRange

// PortRange represents a range of ports.
// Start and End are inclusive. [Start, End]
type PortRange struct {
	Start, End uint16
}

// ParsePortUnion parses a string of comma-separated port ranges (or single ports) into a PortUnion.
// Returns nil if the input is invalid.
// The returned PortUnion is guaranteed to be normalized.
func ParsePortUnion(s string) PortUnion {
	if s == "all" || s == "*" {
		// Wildcard special case
		return PortUnion{PortRange{0, 65535}}
	}
	var result PortUnion
	portStrs := strings.Split(s, ",")
	for _, portStr := range portStrs {
		if strings.Contains(portStr, "-") {
			// Port range
			portRange := strings.Split(portStr, "-")
			if len(portRange) != 2 {
				return nil
			}
			start, err := strconv.ParseUint(portRange[0], 10, 16)
			if err != nil {
				return nil
			}
			end, err := strconv.ParseUint(portRange[1], 10, 16)
			if err != nil {
				return nil
			}
			if start > end {
				start, end = end, start
			}
			result = append(result, PortRange{uint16(start), uint16(end)})
		} else {
			// Single port
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return nil
			}
			result = append(result, PortRange{uint16(port), uint16(port)})
		}
	}
	if result == nil {
		return nil
	}
	return result.Normalize()
}

// Normalize normalizes a PortUnion.
// No overlapping ranges, ranges are sorted from low to high.
func (u PortUnion) Normalize() PortUnion {
	if len(u) == 0 {
		return u
	}
	sort.Slice(u, func(i, j int) bool {
		if u[i].Start == u[j].Start {
			return u[i].End < u[j].End
		}
		return u[i].Start < u[j].Start
	})
	normalized := PortUnion{u[0]}
	for _, current := range u[1:] {
		last := &normalized[len(normalized)-1]
		if uint32(current.Start) <= uint32(last.End)+1 {
			if current.End > last.End {
				last.End = current.End
			}
		} else {
			normalized = append(normalized, current)
		}
	}
	return normalized
}

// Ports returns all ports in the PortUnion as a slice.
func (u PortUnion) Ports() []uint16 {
	var ports []uint16
	for _, r := range u {
		for i := uint32(r.Start); i <= uint32(r.End); i++ {
			ports = append(ports, uint16(i))
		}
	}
	return ports
}
