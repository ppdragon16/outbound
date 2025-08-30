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

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	bufReader io.Reader

	bloom *disk_bloom.FilterGroup
}

type Key struct {
	CipherConf *ciphers.CipherConf
	MasterKey  []byte
}

func NewTCPConn(conn net.Conn, conf *ciphers.CipherConf, masterKey []byte, sg SaltGenerator, addr *socks5.AddressInfo, bloom *disk_bloom.FilterGroup) net.Conn {
	tcpConn := &TCPConn{
		Conn:       conn,
		addr:       addr,
		cipherConf: conf,
		masterKey:  masterKey,
		sg:         sg,
		nonceRead:  make([]byte, conf.NonceLen),
		nonceWrite: make([]byte, conf.NonceLen),
		bloom:      bloom,
	}
	if _, ok := conn.(netproxy.CloseWriter); ok {
		return &netproxy.CloseWriteConn{Conn: tcpConn, CloseWriter: conn.(netproxy.CloseWriter)}
	}
	return tcpConn
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if c.bufReader != nil {
		n, err = c.bufReader.Read(b)
		if err != nil {
			c.bufReader = nil
			if err != io.EOF {
				return 0, err
			}
		}
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
		c.bufReader = bytes.NewReader(payload[n:])
	}
	return n, nil
}

func (c *TCPConn) readChunk() ([]byte, error) {
	payloadLength := pool.GetBuffer(2 + c.cipherConf.TagLen)
	defer pool.PutBuffer(payloadLength)
	if _, err := io.ReadFull(c.Conn, payloadLength); err != nil {
		return nil, err
	}
	_, err := c.cipherRead.Open(payloadLength[:0], c.nonceRead, payloadLength, nil)
	if err != nil {
		return nil, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	l := binary.BigEndian.Uint16(payloadLength)
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
	chunkLengthBuf := pool.GetBuffer(2)
	defer pool.PutBuffer(chunkLengthBuf)
	for i := 0; i < len(payload); i += TCPChunkMaxLen {
		// write chunk
		var chunkLength = common.Min(TCPChunkMaxLen, len(payload)-i)
		binary.BigEndian.PutUint16(chunkLengthBuf, uint16(chunkLength))
		buf.Write(c.cipherWrite.Seal(nil, c.nonceWrite, chunkLengthBuf, nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		buf.Write(c.cipherWrite.Seal(nil, c.nonceWrite, payload[i:i+chunkLength], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
	}
}
