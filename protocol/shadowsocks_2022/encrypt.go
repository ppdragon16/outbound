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

func GenerateSubKey(psk []byte, salt []byte, context string) (subKey []byte) {
	// TODO: SaltLen or KeyLen
	subKey = pool.GetBuffer(len(psk))
	keyMaterial := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(keyMaterial)
	keyMaterial.Write(psk)
	keyMaterial.Write(salt)
	blake3.DeriveKey(subKey, context, keyMaterial.Bytes())
	return
}

func CreateCipher(masterKey []byte, salt []byte, cipherConf *ciphers.CipherConf2022) (cipher cipher.AEAD, err error) {
	subKey := GenerateSubKey(masterKey, salt, Shadowsocks2022ReusedInfo)
	defer pool.PutBuffer(subKey)
	return cipherConf.NewCipher(subKey)
}
