package shadowsocks

import (
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"golang.org/x/crypto/hkdf"
)

const (
	TCPChunkMaxLen = (1 << (16 - 2)) - 1
)

var (
	ErrFailInitCipher = fmt.Errorf("fail to initiate cipher")
)

// TCPConn represents a Shadowsocks TCP connection
type TCPConn struct {
	net.Conn
	addr       *AddressInfo
	cipherConf *ciphers.CipherConf
	masterKey  []byte
	sg         SaltGenerator

	cipherRead  cipher.AEAD
	cipherWrite cipher.AEAD
	onceRead    bool
	onceWrite   bool
	nonceRead   []byte
	nonceWrite  []byte

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	leftToRead  []byte
	indexToRead int

	bloom *disk_bloom.FilterGroup
}

type Key struct {
	CipherConf *ciphers.CipherConf
	MasterKey  []byte
}

func EncryptedPayloadLen(plainTextLen int, tagLen int) int {
	n := plainTextLen / TCPChunkMaxLen
	if plainTextLen%TCPChunkMaxLen > 0 {
		n++
	}
	return plainTextLen + n*(2+tagLen+tagLen)
}

func NewTCPConn(conn net.Conn, conf *ciphers.CipherConf, masterKey []byte, sg SaltGenerator, addr *AddressInfo, bloom *disk_bloom.FilterGroup) (crw *TCPConn, err error) {
	return &TCPConn{
		Conn:       conn,
		addr:       addr,
		cipherConf: conf,
		masterKey:  masterKey,
		sg:         sg,
		nonceRead:  make([]byte, conf.NonceLen),
		nonceWrite: make([]byte, conf.NonceLen),
		bloom:      bloom,
	}, nil
}

func (c *TCPConn) Close() error {
	return c.Conn.Close()
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if !c.onceRead {
		var salt = pool.Get(c.cipherConf.SaltLen)
		defer pool.Put(salt)
		n, err = io.ReadFull(c.Conn, salt)
		if err != nil {
			return
		}
		if c.bloom != nil {
			if c.bloom.ExistOrAdd(salt) {
				err = protocol.ErrReplayAttack
				return
			}
		}
		//log.Warn("salt: %v", hex.EncodeToString(salt))
		subKey := pool.Get(c.cipherConf.KeyLen)
		defer pool.Put(subKey)
		kdf := hkdf.New(
			sha1.New,
			c.masterKey,
			salt,
			ciphers.ShadowsocksReusedInfo,
		)
		_, err = io.ReadFull(kdf, subKey)
		if err != nil {
			return
		}
		c.cipherRead, err = c.cipherConf.NewCipher(subKey)
		if err != nil {
			return 0, fmt.Errorf("%v: %w", ErrFailInitCipher, err)
		}
		c.onceRead = true
	}
	if c.indexToRead < len(c.leftToRead) {
		n = copy(b, c.leftToRead[c.indexToRead:])
		c.indexToRead += n
		if c.indexToRead >= len(c.leftToRead) {
			// Put the buf back
			pool.Put(c.leftToRead)
		}
		return n, nil
	}
	// Chunk
	chunk, err := c.readChunkFromPool()
	if err != nil {
		return 0, err
	}
	n = copy(b, chunk)
	if n < len(chunk) {
		// Wait for the next read
		c.leftToRead = chunk
		c.indexToRead = n
	} else {
		// Full reading. Put the buf back
		pool.Put(chunk)
	}
	return n, nil
}

func (c *TCPConn) readChunkFromPool() ([]byte, error) {
	bufLen := pool.Get(2 + c.cipherConf.TagLen)
	defer pool.Put(bufLen)
	//log.Warn("len(bufLen): %v, c.nonceRead: %v", len(bufLen), c.nonceRead)
	if _, err := io.ReadFull(c.Conn, bufLen); err != nil {
		return nil, err
	}
	bLenPayload, err := c.cipherRead.Open(bufLen[:0], c.nonceRead, bufLen, nil)
	if err != nil {
		//log.Warn("read length of payload: %v: %v", protocol.ErrFailAuth, err)
		return nil, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	lenPayload := binary.BigEndian.Uint16(bLenPayload)
	bufPayload := pool.Get(int(lenPayload) + c.cipherConf.TagLen) // delay putting back
	if _, err = io.ReadFull(c.Conn, bufPayload); err != nil {
		return nil, err
	}
	payload, err := c.cipherRead.Open(bufPayload[:0], c.nonceRead, bufPayload, nil)
	if err != nil {
		//log.Warn("read payload: %v: %v", protocol.ErrFailAuth, err)
		return nil, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	return payload, nil
}

func (c *TCPConn) initWriteFromPool(b []byte) (buf []byte, offset int, payload []byte, err error) {
	// Create address metadata for the first write
	// For client connections, encode the target address
	addressBytes, addressLen, err := EncodeAddress(c.addr)
	if err != nil {
		return nil, 0, nil, err
	}
	// Combine address and data
	payload = pool.Get(addressLen + len(b))
	copy(payload, addressBytes)
	copy(payload[len(addressBytes):], b)
	pool.Put(addressBytes)

	// Generate salt and setup encryption
	buf = pool.Get(c.cipherConf.SaltLen + EncryptedPayloadLen(len(payload), c.cipherConf.TagLen))
	defer func() {
		if err != nil {
			pool.Put(buf)
			pool.Put(payload)
		}
	}()
	salt := c.sg.Get()
	copy(buf, salt)
	pool.Put(salt)
	subKey := pool.Get(c.cipherConf.KeyLen)
	defer pool.Put(subKey)
	kdf := hkdf.New(
		sha1.New,
		c.masterKey,
		buf[:c.cipherConf.SaltLen],
		ciphers.ShadowsocksReusedInfo,
	)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		return nil, 0, nil, err
	}
	c.cipherWrite, err = c.cipherConf.NewCipher(subKey)
	if err != nil {
		return nil, 0, nil, err
	}
	offset += c.cipherConf.SaltLen
	if c.bloom != nil {
		c.bloom.ExistOrAdd(buf[:c.cipherConf.SaltLen])
	}
	//log.Trace("salt(%p): %v", &b, hex.EncodeToString(buf[:c.cipherConf.SaltLen]))
	return
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	var buf, payload []byte
	var offset int
	if !c.onceWrite {
		c.onceWrite = true
		buf, offset, payload, err = c.initWriteFromPool(b)
		if err != nil {
			return 0, err
		}
		defer pool.Put(payload)
	} else {
		buf = pool.Get(EncryptedPayloadLen(len(b), c.cipherConf.TagLen))
		payload = b
	}
	defer pool.Put(buf)
	if c.cipherWrite == nil {
		return 0, fmt.Errorf("%v: %w", ErrFailInitCipher, err)
	}
	c.seal(buf[offset:], payload)
	//log.Trace("to write(%p): %v", &b, hex.EncodeToString(buf[:c.cipherConf.SaltLen]))
	_, err = c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *TCPConn) seal(buf []byte, b []byte) []byte {
	offset := 0
	for i := 0; i < len(b); i += TCPChunkMaxLen {
		// write chunk
		var l = common.Min(TCPChunkMaxLen, len(b)-i)
		binary.BigEndian.PutUint16(buf[offset:], uint16(l))
		_ = c.cipherWrite.Seal(buf[offset:offset], c.nonceWrite, buf[offset:offset+2], nil)
		offset += 2 + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)

		_ = c.cipherWrite.Seal(buf[offset:offset], c.nonceWrite, b[i:i+l], nil)
		offset += l + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)
	}
	return buf[:offset]
}
