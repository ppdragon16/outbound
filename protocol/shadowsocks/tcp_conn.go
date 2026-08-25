package shadowsocks

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/oops"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
)

// TCPChunkMaxLen defines the maximum size of a single SS AEAD chunk payload (16KB - 1).
const TCPChunkMaxLen = (1 << 14) - 1

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
	nonceRead   [12]byte
	nonceWrite  [12]byte

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	bufReader *ReusableReader
	bloom     *disk_bloom.FilterGroup
}

func NewTCPConn(conn net.Conn, conf *ciphers.CipherConf, masterKey []byte, sg SaltGenerator, addr *socks5.AddressInfo, bloom *disk_bloom.FilterGroup) net.Conn {
	tcpConn := &TCPConn{
		Conn:       conn,
		addr:       addr,
		cipherConf: conf,
		masterKey:  masterKey,
		sg:         sg,
		bufReader:  &ReusableReader{},
		bloom:      bloom,
	}
	if cw, ok := conn.(netproxy.CloseWriter); ok {
		return &netproxy.CloseWriteConn{Conn: tcpConn, CloseWriter: cw}
	}
	return tcpConn
}

func (c *TCPConn) Close() error {
	c.bufReader.reset()
	return c.Conn.Close()
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	// 1. Prioritize reading from buffered leftover data (zero-copy)
	if n = c.bufReader.read(b); n > 0 {
		return n, nil
	}

	// 2. Handshake: Receive and verify Salt
	if !c.onceRead {
		var saltStack [64]byte
		salt := saltStack[:c.cipherConf.SaltLen]
		if _, err = io.ReadFull(c.Conn, salt); err != nil {
			return 0, err
		}
		c.cipherRead, err = CreateCipher(c.masterKey, salt, c.cipherConf)
		if err != nil {
			return 0, oops.Wrapf(err, "failed to initiate cipher")
		}
		if c.bloom != nil && c.bloom.ExistOrAdd(salt) {
			return 0, protocol.ErrReplayAttack
		}
		c.onceRead = true
	}

	// 3. Decrypt Chunk Length (2 bytes + Tag)
	var lenStack [32]byte
	lenBufSize := 2 + c.cipherConf.TagLen
	lenBuf := lenStack[:lenBufSize]

	if _, err = io.ReadFull(c.Conn, lenBuf[:lenBufSize]); err != nil {
		return 0, err
	}
	nonceRead := c.nonceRead[:]
	pLenPlain, err := c.cipherRead.Open(lenBuf[:0], nonceRead, lenBuf[:lenBufSize], nil)
	if err != nil {
		return 0, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(nonceRead)
	payloadLength := int(binary.BigEndian.Uint16(pLenPlain))

	// 4. Decrypt Payload Chunk
	totalChunkLen := payloadLength + c.cipherConf.TagLen

	// Fast path: User buffer is large enough for [Payload + Tag]
	if len(b) >= totalChunkLen {
		if _, err = io.ReadFull(c.Conn, b[:totalChunkLen]); err != nil {
			return 0, err
		}
		// In-place decryption directly into user buffer
		_, err = c.cipherRead.Open(b[:0], nonceRead, b[:totalChunkLen], nil)
		common.BytesIncLittleEndian(nonceRead)
		return payloadLength, err
	}

	// Slow path: User buffer is too small, use pool for temporary storage
	tempBuf := pool.GetBuffer(totalChunkLen)
	if _, err = io.ReadFull(c.Conn, tempBuf[:totalChunkLen]); err != nil {
		pool.PutBuffer(tempBuf)
		return 0, err
	}
	decrypted, err := c.cipherRead.Open(tempBuf[:0], nonceRead, tempBuf[:totalChunkLen], nil)
	if err != nil {
		pool.PutBuffer(tempBuf)
		return 0, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(nonceRead)

	// Copy to user buffer and store leftovers
	n = copy(b, decrypted)
	if len(decrypted) > n {
		c.bufReader.fill(tempBuf, n)
	} else {
		pool.PutBuffer(tempBuf)
	}
	return n, nil
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	n = len(b)
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	overhead := (2 + c.cipherConf.TagLen) + c.cipherConf.TagLen

	// Prepare metadata for the first chunk
	var addrMetadata []byte
	if !c.onceWrite {
		var addrStack [512]byte // Large enough for any SOCKS5 address
		aLen, err := socks5.WriteAddrInfoInplace(c.addr, addrStack[:])
		if err != nil {
			return 0, err
		}
		addrMetadata = addrStack[:aLen]
	}

	// Pre-calculate total buffer size to perform a single syscall Write
	totalPlain := len(b) + len(addrMetadata)
	numChunks := (totalPlain + TCPChunkMaxLen - 1) / TCPChunkMaxLen
	if numChunks == 0 {
		numChunks = 1
	} // Ensure at least one chunk for handshake

	totalNeed := 0
	if !c.onceWrite {
		totalNeed += c.cipherConf.SaltLen
	}
	totalNeed += totalPlain + (numChunks * overhead)

	buf := pool.GetBuffer(totalNeed)
	defer pool.PutBuffer(buf)

	curr := 0
	// 1. Initial Handshake: Salt generation
	if !c.onceWrite {
		salt := c.sg.Get(buf[curr : curr+c.cipherConf.SaltLen])
		curr += c.cipherConf.SaltLen
		c.cipherWrite, err = CreateCipher(c.masterKey, salt, c.cipherConf)
		if err != nil {
			return 0, oops.Wrapf(err, "failed to initiate cipher")
		}
		c.onceWrite = true
	}

	remainingB := b
	isFirstChunk := true

	// 2. Fragment data into AEAD chunks
	for isFirstChunk || len(remainingB) > 0 {
		// Calculate current chunk payload composition
		var pPrefix []byte
		if isFirstChunk {
			pPrefix = addrMetadata
			isFirstChunk = false
		}

		bLen := common.Min(len(remainingB), TCPChunkMaxLen-len(pPrefix))
		plainLen := len(pPrefix) + bLen

		// A. Seal Chunk Length (2 bytes)
		var lenStack [2]byte
		binary.BigEndian.PutUint16(lenStack[:], uint16(plainLen))
		nonceWrite := c.nonceWrite[:]
		c.cipherWrite.Seal(buf[curr:curr], nonceWrite, lenStack[:], nil)
		curr += 2 + c.cipherConf.TagLen
		common.BytesIncLittleEndian(nonceWrite)

		// B. Seal Payload Chunk (Metadata + Data)
		payloadStart := curr
		if len(pPrefix) > 0 {
			curr += copy(buf[curr:], pPrefix)
		}
		if bLen > 0 {
			curr += copy(buf[curr:], remainingB[:bLen])
			remainingB = remainingB[bLen:]
		}

		// In-place encryption: dst and src overlap
		c.cipherWrite.Seal(buf[payloadStart:payloadStart], nonceWrite, buf[payloadStart:curr], nil)
		curr += c.cipherConf.TagLen
		common.BytesIncLittleEndian(nonceWrite)
	}

	// 3. Flush everything in a single syscall
	_, err = c.Conn.Write(buf[:curr])
	return n, err
}

type ReusableReader struct {
	data   []byte
	offset int
}

func (r *ReusableReader) fill(data []byte, consumed int) {
	r.data = data
	r.offset = consumed
}

func (r *ReusableReader) read(p []byte) int {
	if r.data == nil {
		return 0
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	if r.offset >= len(r.data) {
		r.reset()
	}
	return n
}

func (r *ReusableReader) reset() {
	if r.data != nil {
		pool.PutBuffer(r.data)
		r.data = nil
	}
	r.offset = 0
}
