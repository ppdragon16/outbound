package shadowsocks_2022

import (
	"crypto/cipher"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
	"lukechampine.com/blake3"
)

var (
	Shadowsocks2022ReusedInfo         = "shadowsocks 2022 session subkey"
	Shadowsocks2022IdentityHeaderInfo = "shadowsocks 2022 identity subkey"
)

func GenerateSubKey(psk []byte, salt []byte, context string) []byte {
	pskLen := len(psk)
	saltLen := len(salt)
	totalLen := pskLen + saltLen
	subKey := pool.GetBuffer(pskLen)

	if totalLen <= 128 { // fast path
		var bufStack [128]byte
		copy(bufStack[:], psk)
		copy(bufStack[pskLen:], salt)
		blake3.DeriveKey(subKey, context, bufStack[:totalLen])
	} else {
		buf := pool.GetBuffer(totalLen)
		copy(buf, psk)
		copy(buf[pskLen:], salt)
		blake3.DeriveKey(subKey, context, buf)
		pool.PutBuffer(buf)
	}
	return subKey
}

func CreateCipher(masterKey []byte, salt []byte, cipherConf *ciphers.CipherConf2022) (cipher cipher.AEAD, err error) {
	subKey := GenerateSubKey(masterKey, salt, Shadowsocks2022ReusedInfo)
	defer pool.PutBuffer(subKey)
	return cipherConf.NewCipher(subKey)
}
