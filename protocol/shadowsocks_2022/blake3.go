package shadowsocks_2022

import (
	"sync"

	"lukechampine.com/blake3/guts"
)

var hasherPool = sync.Pool{
	New: func() any {
		return &Hasher{}
	},
}

func obtainHasher(key [8]uint32, flags uint32) *Hasher {
	h := hasherPool.Get().(*Hasher)
	h.key = key
	h.flags = flags
	h.counter = 0
	h.buflen = 0
	return h
}

func recycleHasher(h *Hasher) {
	hasherPool.Put(h)
}

type Hasher struct {
	key     [8]uint32
	flags   uint32
	stack   [64][8]uint32
	counter uint64
	buf     [guts.ChunkSize]byte
	buflen  int
}

func (h *Hasher) hasSubtreeAtHeight(i int) bool {
	return h.counter&(1<<i) != 0
}

func (h *Hasher) pushSubtree(cv [8]uint32, height int) {
	i := height
	for h.hasSubtreeAtHeight(i) {
		cv = guts.ChainingValue(guts.ParentNode(h.stack[i], cv, &h.key, h.flags))
		i++
	}
	h.stack[i] = cv
	h.counter += 1 << height
}

func (h *Hasher) rootNode() guts.Node {
	n := guts.CompressChunk(h.buf[:h.buflen], &h.key, h.counter, h.flags)
	for i := range 64 {
		if h.hasSubtreeAtHeight(i) {
			n = guts.ParentNode(h.stack[i], guts.ChainingValue(n), &h.key, h.flags)
		}
	}
	n.Flags |= guts.FlagRoot
	return n
}

func (h *Hasher) Write(p []byte) (int, error) {
	lenp := len(p)

	// 处理已有的 buffer
	if h.buflen > 0 {
		n := copy(h.buf[h.buflen:], p)
		h.buflen += n
		p = p[n:]
		if h.buflen == guts.ChunkSize && len(p) > 0 {
			n := guts.CompressChunk(h.buf[:], &h.key, h.counter, h.flags)
			h.pushSubtree(guts.ChainingValue(n), 0)
			h.buflen = 0
		}
	}

	// 处理完整的块 (Synchronous loop)
	for len(p) > guts.ChunkSize {
		n := guts.CompressChunk(p[:guts.ChunkSize], &h.key, h.counter, h.flags)
		h.pushSubtree(guts.ChainingValue(n), 0)
		p = p[guts.ChunkSize:]
	}

	// 缓存剩余字节
	if len(p) > 0 {
		h.buflen = copy(h.buf[:], p)
	}

	return lenp, nil
}

func DeriveKey(subKey []byte, ctx string, srcKey []byte) {
	// 1. 第一步：计算 Context 的派生 IV (256-bit CV)
	h1 := obtainHasher(guts.IV, guts.FlagDeriveKeyContext)
	h1.Write([]byte(ctx))

	// 获取完整的 512-bit 输出，但只取前 256-bit (8个 uint32) 作为 CV
	fullOut1 := guts.CompressNode(h1.rootNode())
	var cv [8]uint32
	copy(cv[:], fullOut1[:8])
	recycleHasher(h1)

	// 2. 第二步：使用派生 CV 作为 Key 计算最终 SubKey
	h2 := obtainHasher(cv, guts.FlagDeriveKeyMaterial)
	h2.Write(srcKey)

	// 因为 subKey <= 32 字节，直接通过一次 CompressNode 即可获取结果
	// guts.WordsToBytes 返回 [64]byte，我们只拷贝需要的长度 (16 或 32)
	fullOut2 := guts.CompressNode(h2.rootNode())
	finalBytes := guts.WordsToBytes(fullOut2)
	copy(subKey, finalBytes[:len(subKey)])

	recycleHasher(h2)
}
