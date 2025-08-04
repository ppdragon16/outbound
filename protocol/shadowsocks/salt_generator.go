package shadowsocks

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/hkdf"
)

type SaltGeneratorType int

const (
	IodizedSaltGeneratorType SaltGeneratorType = iota
	RandomSaltGeneratorType
)

const (
	DefaultTokenLength   = 5
	DefaultBucketSize    = 300
	DefaultHTTPTimeout   = 10 * time.Second
	DefaultIodizedSource = "https://github.com/explore"
)

var (
	DefaultSaltGeneratorType = RandomSaltGeneratorType
)

func NewSaltGenerator(masterKey []byte, saltLen int) (SaltGenerator, error) {
	switch DefaultSaltGeneratorType {
	case IodizedSaltGeneratorType:
		return NewIodizedSaltGenerator(masterKey, saltLen, DefaultBucketSize)
	case RandomSaltGeneratorType:
		return NewRandomSaltGenerator(saltLen)
	default:
		return nil, fmt.Errorf("unknown salt generator type: %v", DefaultSaltGeneratorType)
	}
}

type SaltGenerator interface {
	Get() []byte
	Close() error
}

// IodizedSaltGenerator 使用外部熵源的 salt 生成器
type IodizedSaltGenerator struct {
	tokenBucket chan []byte
	saltSize    int

	mu       sync.RWMutex
	source   []byte
	begin    int
	tokenLen int
	kdfInfo  []byte
	salt     []byte
	cnt      [32]byte

	ctx    context.Context
	cancel context.CancelFunc
}

func NewIodizedSaltGenerator(salt []byte, saltSize, bucketSize int) (*IodizedSaltGenerator, error) {
	// 获取外部熵源
	source, kdfInfo, err := fetchEntropySource(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch entropy source: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	g := &IodizedSaltGenerator{
		tokenBucket: make(chan []byte, bucketSize),
		saltSize:    saltSize,
		source:      source,
		begin:       0,
		tokenLen:    DefaultTokenLength,
		kdfInfo:     kdfInfo,
		salt:        append([]byte(nil), salt...), // 复制 salt 避免外部修改
		ctx:         ctx,
		cancel:      cancel,
	}
	go g.start()

	return g, nil
}

func fetchEntropySource(salt []byte) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", DefaultIodizedSource, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	if len(body) == 0 {
		return nil, nil, fmt.Errorf("empty response body")
	}

	// 生成 KDF info
	var rnd [2]byte
	fastrand.Read(rnd[:])
	h := sha1.New()
	h.Write(rnd[:])
	h.Write(salt)
	kdfInfo := h.Sum(body)

	return body, kdfInfo, nil
}

func (g *IodizedSaltGenerator) start() {
	for {
		salt := g.generateSalt()
		if salt == nil {
			continue
		}

		select {
		case <-g.ctx.Done():
			pool.PutBuffer(salt)
			return
		case g.tokenBucket <- salt:
		}
	}
}

func (g *IodizedSaltGenerator) generateSalt() (salt []byte) {
	salt = pool.GetBuffer(g.saltSize)

	g.mu.Lock()

	tokenEnd := g.begin + g.tokenLen
	if tokenEnd > len(g.source) {
		g.begin = 0
		g.tokenLen++
		tokenEnd = g.begin + g.tokenLen
	}

	kdf := hkdf.New(sha1.New, g.source[g.begin:tokenEnd], g.cnt[:], g.kdfInfo)
	g.begin += g.tokenLen / 3
	common.BytesIncBigEndian(g.cnt[:])

	g.mu.Unlock()

	// 检查是否需要刷新熵源
	if g.tokenLen >= 100 {
		go g.refreshSource()
	}

	if _, err := io.ReadFull(kdf, salt); err != nil {
		panic(fmt.Sprintf("IodizedSaltGenerator.start: %v", err))
	}

	return
}

// refreshSource 刷新外部熵源
func (g *IodizedSaltGenerator) refreshSource() {
	newSource, newKdfInfo, err := fetchEntropySource(g.salt)
	if err != nil {
		g.Close()
		return
	}

	g.mu.Lock()
	g.source = newSource
	g.kdfInfo = newKdfInfo
	g.begin = 0
	g.tokenLen = DefaultTokenLength
	g.mu.Unlock()
}

func (g *IodizedSaltGenerator) Get() []byte {
	return <-g.tokenBucket
}

func (g *IodizedSaltGenerator) Close() error {
	g.cancel()

	close(g.tokenBucket)
	for salt := range g.tokenBucket {
		pool.PutBuffer(salt)
	}

	return nil
}

// RandomSaltGenerator 随机 salt 生成器
type RandomSaltGenerator struct {
	saltSize int
}

func NewRandomSaltGenerator(saltSize int) (*RandomSaltGenerator, error) {
	return &RandomSaltGenerator{
		saltSize: saltSize,
	}, nil
}

func (g *RandomSaltGenerator) Get() []byte {
	salt := pool.GetBuffer(g.saltSize)
	fastrand.Read(salt)
	return salt
}

func (g *RandomSaltGenerator) Close() error {
	return nil
}
