package juicity

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"io"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
)

// fastHKDFSHA1 computes HKDF-SHA1 and fills out in-place.
// Assumes len(out) <= 40 (sufficient for SS key sizes).
func fastHKDFSHA1(secret, salt, info, out []byte) {
	// 1. Extract: PRK = HMAC-SHA1(salt, secret)
	var prk [20]byte
	computeHMACSHA1(salt, prk[:], secret)

	// 2. Expand T(1) = HMAC-SHA1(PRK, info + 0x01)
	var t1 [20]byte
	computeHMACSHA1(prk[:], t1[:], info, []byte{0x01})
	n := copy(out, t1[:])

	// 3. If more bytes needed (e.g. AES-256 needs 32 bytes)
	if n < len(out) {
		// T(2) = HMAC-SHA1(PRK, T(1) + info + 0x02)
		computeHMACSHA1(prk[:], out[n:], t1[:], info, []byte{0x02})
	}
}

// computeHMACSHA1 computes HMAC-SHA1 and writes result to out (must be >= 20 bytes).
// data supports multiple slices to avoid intermediate concatenation.
func computeHMACSHA1(key []byte, out []byte, data ...[]byte) {
	var ipad, opad [64]byte
	var k0 [64]byte

	if len(key) > 64 {
		s := sha1.Sum(key)
		copy(k0[:], s[:])
	} else {
		copy(k0[:], key)
	}

	for i := 0; i < 64; i++ {
		ipad[i] = k0[i] ^ 0x36
		opad[i] = k0[i] ^ 0x5c
	}

	inner := hmac.New(sha1.New, ipad[:])
	for _, d := range data {
		inner.Write(d)
	}
	innerHash := inner.Sum(nil)

	outer := hmac.New(sha1.New, opad[:])
	outer.Write(innerHash)
	copy(out, outer.Sum(nil))
}

func createJuicityCipher(masterKey []byte, salt []byte, cipherConf *ciphers.CipherConf) (cipher.AEAD, error) {
	subKey := pool.GetBuffer(cipherConf.KeyLen)
	fastHKDFSHA1(masterKey, salt, ciphers.JuicityReusedInfo, subKey)
	ciph, err := cipherConf.NewCipher(subKey)
	pool.PutBuffer(subKey)
	return ciph, err
}

// encryptJuicityUDP encrypts plaintext with AEAD, prepending salt.
// Returns a buffer from pool that MUST be returned via pool.PutBuffer.
func encryptJuicityUDP(masterKey []byte, plaintext []byte, salt []byte, cipherConf *ciphers.CipherConf) ([]byte, error) {
	buf := pool.GetBuffer(cipherConf.SaltLen + len(plaintext) + cipherConf.TagLen)
	copy(buf, salt)

	ciph, err := createJuicityCipher(masterKey, salt, cipherConf)
	if err != nil {
		pool.PutBuffer(buf)
		return nil, err
	}
	ciph.Seal(buf[cipherConf.SaltLen:cipherConf.SaltLen], ciphers.ZeroNonce[:cipherConf.NonceLen], plaintext, nil)
	return buf, nil
}

// decryptJuicityUDP decrypts shadowBytes in-place.
func decryptJuicityUDP(masterKey []byte, shadowBytes []byte, cipherConf *ciphers.CipherConf) ([]byte, error) {
	if len(shadowBytes) < cipherConf.SaltLen {
		return nil, io.ErrUnexpectedEOF
	}
	ciph, err := createJuicityCipher(masterKey, shadowBytes[:cipherConf.SaltLen], cipherConf)
	if err != nil {
		return nil, err
	}
	return ciph.Open(shadowBytes[:0], ciphers.ZeroNonce[:cipherConf.NonceLen], shadowBytes[cipherConf.SaltLen:], nil)
}
