package shadowsocks_2022

import (
	"crypto/cipher"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
	"lukechampine.com/blake3"
)

var (
	Shadowsocks2022ReusedInfo = "shadowsocks 2022 session subkey"
)

func GenerateSubKey(masterKey []byte, salt []byte) (subKey []byte, err error) {
	// TODO: SaltLen or KeyLen
	subKey = pool.GetBuffer(len(masterKey))
	keyMaterial := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(keyMaterial)
	keyMaterial.Write(masterKey)
	keyMaterial.Write(salt)
	blake3.DeriveKey(subKey, Shadowsocks2022ReusedInfo, keyMaterial.Bytes())
	return
}

func CreateCipher(masterKey []byte, salt []byte, cipherConf *ciphers.CipherConf2022) (cipher cipher.AEAD, err error) {
	subKey, err := GenerateSubKey(masterKey, salt)
	defer pool.PutBuffer(subKey)
	if err != nil {
		return nil, err
	}
	return cipherConf.NewCipher(subKey)
}
