package anytls

import (
	"crypto/md5"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync/atomic"
)

const CheckMark = -1

var (
	defaultPaddingScheme = []byte(`stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)
	settingsBytes = func(padding *paddingFactory) []byte {
		return fmt.Appendf(nil, "v=2\nclient=dae\npadding-md5=%s", padding.Md5)
	}
)

var DefaultPaddingFactory atomic.Pointer[paddingFactory]

// paddingRange is one pre-compiled element of a packet's padding rule.
// kind is either paddingKindFixed (min==max, deterministic size),
// paddingKindRange (random size in [min, max]), or paddingKindCheckMark (-1).
type paddingRange struct {
	kind byte
	min  int
	max  int
}

const (
	paddingKindFixed     byte = 0
	paddingKindRange     byte = 1
	paddingKindCheckMark byte = 2
)

type paddingFactory struct {
	// rules maps a 1-based packet counter to its pre-compiled rule list.
	// Looked up on the write hot path; values are immutable after construction.
	rules     map[uint32][]paddingRange
	RawScheme []byte
	Stop      uint32
	Md5       string
}

func init() {
	updatePaddingScheme(defaultPaddingScheme)
}

func updatePaddingScheme(rawScheme []byte) bool {
	if p := NewPaddingFactory(rawScheme); p != nil {
		DefaultPaddingFactory.Store(p)
		return true
	}
	return false
}

func stringMapFromBytes(b []byte) map[string]string {
	m := make(map[string]string)
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		v := strings.SplitN(line, "=", 2)
		if len(v) == 2 {
			m[v[0]] = v[1]
		}
	}
	return m
}

func NewPaddingFactory(rawScheme []byte) *paddingFactory {
	rawScheme = append([]byte(nil), rawScheme...)
	p := &paddingFactory{
		RawScheme: rawScheme,
		Md5:       fmt.Sprintf("%x", md5.Sum(rawScheme)),
	}
	scheme := stringMapFromBytes(rawScheme)
	if len(scheme) == 0 {
		return nil
	}
	stop, err := strconv.Atoi(scheme["stop"])
	if err != nil {
		return nil
	}
	p.Stop = uint32(stop)

	// Pre-compile every "pkt=ranges" entry once, so the write hot path
	// avoids re-parsing strings / strconv on every frame. Invalid entries
	// are dropped (same tolerance as the previous parse-on-each-call impl).
	rules := make(map[uint32][]paddingRange, len(scheme)-1)
	for k, v := range scheme {
		if k == "stop" {
			continue
		}
		pktNum, err := strconv.ParseUint(k, 10, 32)
		if err != nil {
			continue
		}
		compiled := compileRanges(v)
		if len(compiled) == 0 {
			continue
		}
		rules[uint32(pktNum)] = compiled
	}
	p.rules = rules
	return p
}

// compileRanges parses a comma-separated "min-max" / "c" rule list once.
// Output order matches the source text, preserving protocol framing semantics.
func compileRanges(spec string) []paddingRange {
	sRanges := strings.Split(spec, ",")
	out := make([]paddingRange, 0, len(sRanges))
	for _, sRange := range sRanges {
		sRangeMinMax := strings.Split(sRange, "-")
		if len(sRangeMinMax) == 2 {
			lo, err := strconv.ParseInt(sRangeMinMax[0], 10, 64)
			if err != nil {
				continue
			}
			hi, err := strconv.ParseInt(sRangeMinMax[1], 10, 64)
			if err != nil {
				continue
			}
			lo, hi = min(lo, hi), max(lo, hi)
			if lo <= 0 || hi <= 0 {
				continue
			}
			if lo == hi {
				out = append(out, paddingRange{kind: paddingKindFixed, min: int(lo)})
			} else {
				out = append(out, paddingRange{kind: paddingKindRange, min: int(lo), max: int(hi)})
			}
		} else if sRange == "c" {
			out = append(out, paddingRange{kind: paddingKindCheckMark})
		}
	}
	return out
}

// GenerateRecordPayloadSizes returns the payload size sequence for packet
// number pkt (1-based). Each element is either a positive payload length or
// CheckMark (-1). Hot path: no string parsing, no crypto/rand syscall.
func (p *paddingFactory) GenerateRecordPayloadSizes(pkt uint32) (pktSizes []int) {
	ranges, ok := p.rules[pkt]
	if !ok {
		return nil
	}
	pktSizes = make([]int, len(ranges))
	for i, r := range ranges {
		switch r.kind {
		case paddingKindFixed:
			pktSizes[i] = r.min
		case paddingKindRange:
			// IntN returns [0, max-min]; offset by min. math/rand/v2 is
			// concurrent-safe and seeded from the runtime; padding only
			// needs traffic-shaping randomness, not cryptographic strength.
			pktSizes[i] = r.min + rand.IntN(r.max-r.min)
		case paddingKindCheckMark:
			pktSizes[i] = CheckMark
		}
	}
	return pktSizes
}
