package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/samber/oops"
	"lukechampine.com/blake3"
)

const (
	TCPChunkMaxLen = (1 << 16) - 1

	HeaderTypeClientStream = 0
	HeaderTypeServerStream = 1
	MinPaddingLength       = 0
	MaxPaddingLength       = 900

	initWriteBufSize = 2048
)

// TCPConn represents a Shadowsocks TCP connection
type TCPConn struct {
	net.Conn
	addr       *socks5.AddressInfo
	cipherConf *ciphers.CipherConf2022
	pskList    [][]byte
	uPSK       []byte
	sg         shadowsocks.SaltGenerator

	cipherRead  cipher.AEAD
	cipherWrite cipher.AEAD
	onceRead    bool
	onceWrite   bool

	nonceRead        []byte
	nonceWrite       []byte
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

func NewTCPConn(conn net.Conn, conf *ciphers.CipherConf2022, pskList [][]byte, uPSK []byte, sg shadowsocks.SaltGenerator, addr *socks5.AddressInfo, bloom *disk_bloom.FilterGroup) net.Conn {
	tcpConn := &TCPConn{
		Conn:             conn,
		addr:             addr,
		cipherConf:       conf,
		pskList:          pskList,
		uPSK:             uPSK,
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

	var payloadLength uint16

	if !c.onceRead {
		var salt = pool.GetBuffer(c.cipherConf.SaltLen)
		defer pool.PutBuffer(salt)

		n, err = io.ReadFull(c.Conn, salt)
		if err != nil {
			return 0, err
		}
		c.cipherRead, err = CreateCipher(c.uPSK, salt, c.cipherConf)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to initiate cipher")
		}

		header := pool.GetBuffer(11 + c.cipherConf.SaltLen + c.cipherConf.TagLen)
		defer pool.PutBuffer(header)
		if _, err := io.ReadFull(c.Conn, header); err != nil {
			return 0, err
		}
		header, err := c.cipherRead.Open(header[:0], c.nonceRead, header, nil)
		if err != nil {
			return 0, protocol.ErrFailAuth
		}
		common.BytesIncLittleEndian(c.nonceRead)
		offset := 0
		typ := uint8(header[offset])
		offset += 1
		timestamp := time.Unix(int64(binary.BigEndian.Uint64(header[offset:offset+8])), 0)
		offset += 8

		if typ != HeaderTypeServerStream {
			return 0, fmt.Errorf("received unexpected header type: %d", typ)
		}

		if timestamp.Before(time.Now().Add(-ciphers.TimestampTolerance)) {
			return 0, protocol.ErrReplayAttack
		}

		// TODO: 不应该使用 bloom filter
		if c.bloom != nil {
			if c.bloom.ExistOrAdd(salt) {
				return 0, protocol.ErrReplayAttack
			}
		}

		// Skip request salt
		offset += c.cipherConf.SaltLen

		payloadLength = binary.BigEndian.Uint16(header[offset : offset+2])

		c.onceRead = true
	} else {
		if _, err := io.ReadFull(c.Conn, c.payloadLengthBuf); err != nil {
			return 0, err
		}
		payloadLenBuf, err := c.cipherRead.Open(c.payloadLengthBuf[:0], c.nonceRead, c.payloadLengthBuf, nil)
		if err != nil {
			return 0, protocol.ErrFailAuth
		}
		common.BytesIncLittleEndian(c.nonceRead)
		payloadLength = binary.BigEndian.Uint16(payloadLenBuf)
	}

	if c.cipherRead == nil {
		return 0, oops.Wrapf(err, "cipher is not initialized")
	}

	payload := pool.GetBuffer(int(payloadLength) + c.cipherConf.TagLen)
	if _, err = io.ReadFull(c.Conn, payload); err != nil {
		return 0, err
	}
	payload, err = c.cipherRead.Open(payload[:0], c.nonceRead, payload, nil)
	if err != nil {
		return 0, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)

	n = copy(b, payload)
	if len(payload) > n {
		c.bufReader.fill(payload, n)
	} else {
		pool.PutBuffer(payload)
	}
	return n, nil
}

func EncodeRequestHeader(typ uint8, timestamp uint64, addressInfo *socks5.AddressInfo, b *[]byte) (*bytes.Buffer, *bytes.Buffer, error) {
	fixedHeader := pool.GetBytesBuffer()
	varHeader := pool.GetBytesBuffer()

	// Variable-length header: address (variable) + paddingLength (2) + padding (variable, 0) + payload (variable)
	if err := socks5.WriteAddrInfo(addressInfo, varHeader); err != nil {
		return nil, nil, err
	}
	// No padding
	binary.Write(varHeader, binary.BigEndian, uint16(0))
	initialPayloadMaxLength := TCPChunkMaxLen - varHeader.Len()
	var n int
	if len(*b) > initialPayloadMaxLength {
		varHeader.Write((*b)[:initialPayloadMaxLength])
		n = initialPayloadMaxLength
	} else {
		varHeader.Write(*b)
		n = len(*b)
	}
	*b = (*b)[n:]

	// Fixed-length header: type (1) + timestamp (8) + length (2) = 11 bytes
	fixedHeader.WriteByte(typ)
	binary.Write(fixedHeader, binary.BigEndian, timestamp)
	binary.Write(fixedHeader, binary.BigEndian, uint16(varHeader.Len()))

	return fixedHeader, varHeader, nil
}

func (c *TCPConn) writeIdentityHeader(buf *bytes.Buffer, salt []byte) error {
	identityHeader := pool.GetBuffer(aes.BlockSize)
	defer pool.PutBuffer(identityHeader)
	for i := 0; i < len(c.pskList)-1; i++ {
		identity_subkey := GenerateSubKey(c.pskList[i], salt, Shadowsocks2022IdentityHeaderInfo)
		plaintext := blake3.Sum512(c.pskList[i+1])
		b, err := c.cipherConf.NewBlockCipher(identity_subkey)
		if err != nil {
			return err
		}
		b.Encrypt(identityHeader, plaintext[:aes.BlockSize])
		buf.Write(identityHeader)
	}
	return nil
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	n = len(b)
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if !c.onceWrite {
		// Generate salt
		salt := c.sg.Get()
		defer pool.PutBuffer(salt)
		buf.Write(salt)

		err := c.writeIdentityHeader(buf, salt)
		if err != nil {
			debug.PrintStack()
			return 0, oops.Wrapf(err, "fail to write identity header")
		}

		// Setup encryption
		c.cipherWrite, err = CreateCipher(c.uPSK, salt, c.cipherConf)
		if err != nil {
			debug.PrintStack()
			return 0, oops.Wrapf(err, "fail to initiate cipher")
		}

		// Add Request headers
		fixedHeader, varHeader, err := EncodeRequestHeader(HeaderTypeClientStream, uint64(time.Now().Unix()), c.addr, &b)
		defer pool.PutBytesBuffer(fixedHeader)
		defer pool.PutBytesBuffer(varHeader)
		if err != nil {
			debug.PrintStack()
			return 0, oops.Wrapf(err, "fail to encode request header")
		}
		buf.Write(c.cipherWrite.Seal(c.prepareWriteBuf(fixedHeader.Len()), c.nonceWrite, fixedHeader.Bytes(), nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		buf.Write(c.cipherWrite.Seal(c.prepareWriteBuf(varHeader.Len()), c.nonceWrite, varHeader.Bytes(), nil))
		common.BytesIncLittleEndian(c.nonceWrite)

		c.onceWrite = true
	}
	if c.cipherWrite == nil {
		debug.PrintStack()
		return 0, oops.Wrapf(err, "cipher is not initialized")
	}
	// Seal.
	var chunkLengthBuf [2]byte
	for i := 0; i < len(b); i += TCPChunkMaxLen {
		// write chunk
		var chunkLength = common.Min(TCPChunkMaxLen, len(b)-i)
		binary.BigEndian.PutUint16(chunkLengthBuf[:], uint16(chunkLength))
		buf.Write(c.cipherWrite.Seal(c.prepareWriteBuf(2), c.nonceWrite, chunkLengthBuf[:], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
		buf.Write(c.cipherWrite.Seal(c.prepareWriteBuf(chunkLength), c.nonceWrite, b[i:i+chunkLength], nil))
		common.BytesIncLittleEndian(c.nonceWrite)
	}
	_, err = c.Conn.Write(buf.Bytes())
	return n, err
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
