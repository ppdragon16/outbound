package shadowsocks_2022

import (
	"crypto/cipher"
	"fmt"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
)

var (
	Shadowsocks2022ReusedInfo         = "shadowsocks 2022 session subkey"
	Shadowsocks2022IdentityHeaderInfo = "shadowsocks 2022 identity subkey"
)

func GenerateSubKey(psk []byte, salt []byte, context string, subKeyBuf []byte) []byte {
	pskLen := len(psk)
	saltLen := len(salt)
	totalLen := pskLen + saltLen

	if totalLen <= 128 { // fast path
		var bufStack [128]byte
		copy(bufStack[:], psk)
		copy(bufStack[pskLen:], salt)
		DeriveKey(subKeyBuf, context, bufStack[:totalLen])
	} else {
		buf := pool.GetBuffer(totalLen)
		copy(buf, psk)
		copy(buf[pskLen:], salt)
		DeriveKey(subKeyBuf, context, buf)
		pool.PutBuffer(buf)
	}
	return subKeyBuf
}

func CreateCipher(masterKey []byte, salt []byte, cipherConf *ciphers.CipherConf2022) (cipher cipher.AEAD, err error) {
	var subKeyBuf [32]byte
	if cipherConf.KeyLen > len(subKeyBuf) {
		return nil, fmt.Errorf("unsupported key length: %d", cipherConf.KeyLen)
	}
	return cipherConf.NewCipher(GenerateSubKey(masterKey, salt, Shadowsocks2022ReusedInfo, subKeyBuf[:cipherConf.KeyLen]))
}
