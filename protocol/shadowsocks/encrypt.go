package shadowsocks

import (
	"crypto/cipher"
	"crypto/sha1"

	"github.com/daeuniverse/outbound/ciphers"
)

var (
	ShadowsocksReusedInfo = []byte("ss-subkey")
)

func CreateCipher(masterKey []byte, salt []byte, cipherConf *ciphers.CipherConf) (cipher.AEAD, error) {
	// 1. 栈分配 subKey 空间 (16 或 32 字节)
	var subKeyBuf [32]byte
	subKey := subKeyBuf[:len(masterKey)]

	// 2. 调用零分配 HKDF 填充 subKey
	// 注意：ShadowsocksReusedInfo 是静态定义的 []byte("ss-subkey")
	fastHKDFSHA1(masterKey, salt, ShadowsocksReusedInfo, subKey)

	// 3. 创建 AEAD 对象
	// 虽然 subKey 在栈上，但 NewCipher 内部的 NewGCM 仍然会产生分配
	// (因为 AEAD 接口对象必须逃逸到堆上供后续 Read/Write 使用)
	return cipherConf.NewCipher(subKey)
}

// fastHKDFSHA1 计算 HKDF-SHA1 并在 out 中原地填充。
// 假设 out 长度 <= 40 (SS 场景下足够)。
func fastHKDFSHA1(secret, salt, info, out []byte) {
	// 1. Extract: PRK = HMAC-SHA1(salt, secret)
	var prk [20]byte
	computeHMACSHA1(salt, prk[:], secret)

	// 2. Expand T(1) = HMAC-SHA1(PRK, info + 0x01)
	var t1 [20]byte
	computeHMACSHA1(prk[:], t1[:], info, []byte{0x01})
	n := copy(out, t1[:])

	// 3. 如果需要更多长度 (例如 AES-256 需要 32 字节)
	if n < len(out) {
		// T(2) = HMAC-SHA1(PRK, T(1) + info + 0x02)
		computeHMACSHA1(prk[:], out[n:], t1[:], info, []byte{0x02})
	}
}

// computeHMACSHA1 计算 HMAC-SHA1 并将结果写入 out (需确保 out 长度至少 20)。
// data 参数支持传入多个切片以模拟 h.Write 逻辑，避免中途拼接字符串。
func computeHMACSHA1(key []byte, out []byte, data ...[]byte) {
	var ipad, opad [64]byte
	var k0 [64]byte

	// 1. 准备 K0
	if len(key) > 64 {
		// 如果 key 太长，先 hash 一次
		s := sha1.Sum(key)
		copy(k0[:], s[:])
	} else {
		copy(k0[:], key)
	}

	// 2. 计算 ipad 和 opad
	for i := 0; i < 64; i++ {
		ipad[i] = k0[i] ^ 0x36
		opad[i] = k0[i] ^ 0x5c
	}

	// 3. Inner Hash: H((K ^ ipad) || data...)
	inner := sha1.New()
	inner.Write(ipad[:])
	for _, d := range data {
		inner.Write(d)
	}
	var innerHash [20]byte
	inner.Sum(innerHash[:0]) // 这里的 inner 虽然是 interface，但如果编译器发现不逃逸，开销极小

	// 4. Outer Hash: H((K ^ opad) || innerHash)
	outer := sha1.New()
	outer.Write(opad[:])
	outer.Write(innerHash[:])
	outer.Sum(out[:0])
}
