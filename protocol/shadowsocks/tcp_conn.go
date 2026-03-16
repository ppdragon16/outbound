package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/samber/oops"
)

const (
	TCPChunkMaxLen = (1 << 14) - 1

	initWriteBufSize = 2048
)

// TCPConn represents a Shadowsocks TCP connection
type TCPConn struct {
	net.Conn
	addr       *socks5.AddressInfo
	cipherConf *ciphers.CipherConf
	masterKey  []byte
	sg         SaltGenerator

	cipherRead  cipher.AEAD
	cipherWrite cipher.AEAD
	onceRead    bool
	onceWrite   bool
	nonceRead   []byte
	nonceWrite  []byte

	payloadLengthBuf []byte

	// writeBuf is used for Seal() to avoid heap allocation
	writeBuf []byte

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	bufReader *ReusableReader

	bloom *disk_bloom.FilterGroup
}

type Key struct {
	CipherConf *ciphers.CipherConf
	MasterKey  []byte
}

func NewTCPConn(conn net.Conn, conf *ciphers.CipherConf, masterKey []byte, sg SaltGenerator, addr *socks5.AddressInfo, bloom *disk_bloom.FilterGroup) net.Conn {
	tcpConn := &TCPConn{
		Conn:             conn,
		addr:             addr,
		cipherConf:       conf,
		masterKey:        masterKey,
		sg:               sg,
		nonceRead:        make([]byte, conf.NonceLen),
		nonceWrite:       make([]byte, conf.NonceLen),
		payloadLengthBuf: pool.GetBuffer(2 + conf.TagLen),
		bufReader:        &ReusableReader{},
		bloom:            bloom,
	}
	if _, ok := conn.(netproxy.CloseWriter); ok {
		return &netproxy.CloseWriteConn{Conn: tcpConn, CloseWriter: conn.(netproxy.CloseWriter)}
	}
	return tcpConn
}

func (c *TCPConn) Close() error {
	pool.PutBuffer(c.payloadLengthBuf)
	pool.PutBuffer(c.writeBuf)
	c.bufReader.reset()
	return c.Conn.Close()
}

// prepareWriteBuf ensures c.writeBuf has enough capacity for the given plaintext length.
// It dynamically grows: 2K -> 4K -> 8K -> ... to avoid heap allocation in Seal().
func (c *TCPConn) prepareWriteBuf(plaintextLen int) []byte {
	needCap := plaintextLen + c.cipherConf.TagLen
	if cap(c.writeBuf) < needCap {
		// Grow: 2K -> 4K -> 8K -> ...
		newCap := initWriteBufSize
		for newCap < needCap {
			newCap *= 2
		}
		pool.PutBuffer(c.writeBuf)
		c.writeBuf = pool.GetBuffer(newCap)
	}
	// Reset length, keep capacity
	return c.writeBuf[:0]
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if n = c.bufReader.read(b); n > 0 {
		return n, nil
	}

	if !c.onceRead {
		var salt = pool.GetBuffer(c.cipherConf.SaltLen)
		defer pool.PutBuffer(salt)

		n, err = io.ReadFull(c.Conn, salt)
		if err != nil {
			return 0, err
		}
		c.cipherRead, err = CreateCipher(c.masterKey, salt, c.cipherConf)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to initiate cipher")
		}
		if c.bloom != nil {
			if c.bloom.ExistOrAdd(salt) {
				return 0, protocol.ErrReplayAttack
			}
		}
		c.onceRead = true
	}
	if c.cipherRead == nil {
		return 0, oops.Wrapf(err, "cipher is not initialized")
	}

	// Chunk
	payload, err := c.readChunk()
	if err != nil {
		return 0, err
	}
	n = copy(b, payload)
	if len(payload) > n {
		c.bufReader.fill(payload, n)
	} else {
		pool.PutBuffer(payload)
	}
	return n, nil
}

func (c *TCPConn) readChunk() ([]byte, error) {
	if _, err := io.ReadFull(c.Conn, c.payloadLengthBuf); err != nil {
		return nil, err
	}
	_, err := c.cipherRead.Open(c.payloadLengthBuf[:0], c.nonceRead, c.payloadLengthBuf, nil)
	if err != nil {
		return nil, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	l := binary.BigEndian.Uint16(c.payloadLengthBuf)
	payload := pool.GetBuffer(int(l) + c.cipherConf.TagLen) // delay putting back
	if _, err = io.ReadFull(c.Conn, payload); err != nil {
		return nil, err
	}
	payload, err = c.cipherRead.Open(payload[:0], c.nonceRead, payload, nil)
	if err != nil {
		return nil, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	return payload, nil
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	buf := pool.GetBytesBuffer()
	payload := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	defer pool.PutBytesBuffer(payload)
	if !c.onceWrite {
		// Generate salt and setup encryption
		salt := c.sg.Get()
		defer pool.PutBuffer(salt)
		c.cipherWrite, err = CreateCipher(c.masterKey, salt, c.cipherConf)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to initiate cipher")
		}
		// Add salt for first write
		buf.Write(salt)

		// Create address metadata for the first write
		// For client connections, encode the target address
		socks5.WriteAddrInfo(c.addr, payload)

		c.onceWrite = true
	}
	if c.cipherWrite == nil {
		return 0, oops.Wrapf(err, "cipher is not initialized")
	}
	payload.Write(b)
	c.seal(buf, payload.Bytes())
	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
}

func (c *TCPConn) seal(buf *bytes.Buffer, payload []byte) {
	var chunkLengthBuf [2]byte
	for i := 0; i < len(payload); i += TCPChunkMaxLen {
		// write chunk
		var chunkLength = common.Min(TCPChunkMaxLen, len(payload)-i)
		binary.BigEndian.PutUint16(chunkLengthBuf[:], uint16(chunkLength))
		buf.Write(c.cipherWrite.Seal(c.prepareWriteBuf(2), c.nonceWrite, chunkLengthBuf[:], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		buf.Write(c.cipherWrite.Seal(c.prepareWriteBuf(chunkLength), c.nonceWrite, payload[i:i+chunkLength], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
	}
}

type ReusableReader struct {
	data   []byte
	offset int
}

func (r *ReusableReader) fill(data []byte, offset int) {
	r.data = data
	r.offset = offset
}

func (r *ReusableReader) read(p []byte) int {
	dataLen := len(r.data)
	if r.offset >= dataLen {
		return 0
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	if r.offset >= dataLen {
		r.reset()
	}
	return n
}

func (r *ReusableReader) reset() {
	pool.PutBuffer(r.data)
	r.data = nil
	r.offset = 0
}
