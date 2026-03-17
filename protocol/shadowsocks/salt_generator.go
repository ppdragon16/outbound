package shadowsocks

import (
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

type SaltGenerator interface {
	Get(buf []byte) []byte
	Close() error
}
type RandomSaltGenerator struct {
	saltSize int
}

func NewRandomSaltGenerator(saltSize int) (*RandomSaltGenerator, error) {
	return &RandomSaltGenerator{
		saltSize: saltSize,
	}, nil
}

func (g *RandomSaltGenerator) Get(buf []byte) []byte {
	fastrand.Read(buf)
	return buf
}

func (g *RandomSaltGenerator) Close() error {
	return nil
}
