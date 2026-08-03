package protocol

import (
	rand "github.com/daeuniverse/outbound/pkg/fastrand"
)

const (
	paddingChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// padding specifies a half-open range [Min, Max).
type padding struct {
	Min int
	Max int
}

// randomLen returns a random padding length in [Min, Max).
func (p padding) randomLen() int {
	if p.Max <= p.Min {
		return p.Min
	}
	return p.Min + rand.Intn(p.Max-p.Min)
}

// writeRandomBytes fills dst with random characters from paddingChars in
// bulk via fastrand.Read, then maps each byte to the character set via
// modulo. Order of magnitude faster than per-byte fastrand.Intn on long
// paddings (authRequest goes up to 2048 bytes).
func writeRandomBytes(dst []byte) {
	if len(dst) == 0 {
		return
	}
	_, _ = rand.Read(dst)
	const n = byte(len(paddingChars))
	for i := range dst {
		dst[i] = paddingChars[dst[i]%n]
	}
}

func (p padding) String() string {
	bs := make([]byte, p.randomLen())
	writeRandomBytes(bs)
	return string(bs)
}

var (
	authRequestPadding  = padding{Min: 256, Max: 2048}
	authResponsePadding = padding{Min: 256, Max: 2048}
	tcpRequestPadding   = padding{Min: 64, Max: 512}
	tcpResponsePadding  = padding{Min: 128, Max: 1024}
)
