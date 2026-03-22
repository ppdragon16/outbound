package shadowsocks_2022

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
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

	writeBuf []byte

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	bufReader *ReusableReader

	bloom       *disk_bloom.FilterGroup
	writeHasher *blake3.Hasher
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

func (c *TCPConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if n = c.bufReader.read(b); n > 0 {
		return n, nil
	}

	var payloadLength int

	if !c.onceRead {
		var stackBuf [128]byte // Enough space for: Salt(32) + Header(11+32+16)
		salt := stackBuf[:c.cipherConf.SaltLen]
		n, err = io.ReadFull(c.Conn, salt)
		if err != nil {
			return 0, err
		}
		c.cipherRead, err = CreateCipher(c.uPSK, salt, c.cipherConf)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to initiate cipher")
		}

		// Fixed Header + Server Salt
		hLen := 11 + c.cipherConf.SaltLen + c.cipherConf.TagLen
		headerRaw := stackBuf[:hLen]
		if _, err := io.ReadFull(c.Conn, headerRaw); err != nil {
			return 0, err
		}
		header, err := c.cipherRead.Open(headerRaw[:0], c.nonceRead, headerRaw, nil)
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

		payloadLength = int(binary.BigEndian.Uint16(header[offset : offset+2]))

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
		payloadLength = int(binary.BigEndian.Uint16(payloadLenBuf))
	}

	if c.cipherRead == nil {
		return 0, oops.Wrapf(err, "cipher is not initialized")
	}

	if len(b) >= payloadLength+c.cipherConf.TagLen {
		// Fast path
		// Uses b for inplace decryption if it's bigger than Payload + Tag
		target := b[:payloadLength+c.cipherConf.TagLen]
		if _, err = io.ReadFull(c.Conn, target); err != nil {
			return 0, err
		}
		_, err = c.cipherRead.Open(b[:0], c.nonceRead, target, nil)
		common.BytesIncLittleEndian(c.nonceRead)
		return payloadLength, err
	}

	// Slow path
	payload := pool.GetBuffer(payloadLength + c.cipherConf.TagLen)
	if _, err = io.ReadFull(c.Conn, payload); err != nil {
		return 0, err
	}
	payload, err = c.cipherRead.Open(payload[:0], c.nonceRead, payload, nil)
	if err != nil {
		pool.PutBuffer(payload)
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

func EncodeRequestHeaderInPlace(typ uint8, ts uint64, addr *socks5.AddressInfo, b []byte, dstFixed []byte, dstVar []byte) (int, int, int, error) {
	// 1. 写入 Variable Header 的地址部分
	curr, err := socks5.WriteAddrInfoInplace(addr, dstVar)
	if err != nil {
		return 0, 0, 0, err
	}

	// 2. 写入 PaddingLen (2 bytes, SS2022 目前固定为 0)
	if len(dstVar) < curr+2 {
		return 0, 0, 0, io.ErrShortBuffer
	}
	binary.BigEndian.PutUint16(dstVar[curr:], 0)

	vHeaderOff := curr + 2

	// 3. 确定 Payload 填充限制 (协议 16KB vs 缓冲区剩余空间)
	vMaxConsumeOff := common.Min(TCPChunkMaxLen, len(dstVar))

	// 4. 执行拷贝并获取实际消耗长度
	consumed := 0
	if vMaxConsumeOff > vHeaderOff {
		consumed = copy(dstVar[vHeaderOff:vMaxConsumeOff], b)
	}
	vTotal := vHeaderOff + consumed

	// 5. 填充 Fixed Header (dstFixed)
	// 布局：Type(1) + Timestamp(8) + VarHeaderLen(2)
	dstFixed[0] = typ
	binary.BigEndian.PutUint64(dstFixed[1:9], ts)
	binary.BigEndian.PutUint16(dstFixed[9:11], uint16(vTotal))

	return 11, vTotal, consumed, nil
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	n = len(b)
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// 1. 预计算总空间，一次性拿够
	totalNeed := c.cipherConf.SaltLen + (len(c.pskList)-1)*16 + 2048 + len(b) + (len(b)/16384+2)*40
	buf := pool.GetBuffer(totalNeed)
	defer pool.PutBuffer(buf)

	curr := 0
	remainingB := b

	if !c.onceWrite {
		// --- A. Salt ---
		salt := buf[curr : curr+c.cipherConf.SaltLen]
		c.sg.Get(salt)
		curr += c.cipherConf.SaltLen

		// 初始化会话加密器
		c.cipherWrite, err = CreateCipher(c.uPSK, salt, c.cipherConf)
		if err != nil {
			return 0, err
		}

		var subKeyBuf [32]byte
		// --- B. Identity Headers ---
		for i := 0; i < len(c.pskList)-1; i++ {
			bc, _ := c.cipherConf.NewBlockCipher(GenerateSubKey(c.pskList[i], salt, Shadowsocks2022IdentityHeaderInfo, subKeyBuf[:c.cipherConf.KeyLen]))
			plaintext := blake3.Sum512(c.pskList[i+1])
			bc.Encrypt(buf[curr:curr+16], plaintext[:16])
			curr += 16
		}

		// --- C. Request Headers (Fixed + Variable) ---
		// 关键改动：先在栈上/临时位置构造明文，再 Seal 到 buf 的 curr 位置
		// 这样可以彻底避免复杂的 Offset 挪动逻辑

		// 预留两个 Header 的明文空间 (Fixed 11 + Var 最大约 1500)
		// 使用一个小的栈空间做中转，确保逻辑清晰
		var headerStack [2048]byte
		fHeader := headerStack[:11]
		vHeader := headerStack[11:]

		fLen, vLen, consumed, err := EncodeRequestHeaderInPlace(
			HeaderTypeClientStream, uint64(time.Now().Unix()),
			c.addr, remainingB, fHeader, vHeader)
		if err != nil {
			return 0, err
		}
		remainingB = remainingB[consumed:]

		// 1. Seal Fixed Header 到 buf
		c.cipherWrite.Seal(buf[curr:curr], c.nonceWrite, fHeader[:fLen], nil)
		curr += fLen + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)

		// 2. Seal Variable Header 到 buf
		c.cipherWrite.Seal(buf[curr:curr], c.nonceWrite, vHeader[:vLen], nil)
		curr += vLen + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)

		c.onceWrite = true
	}

	// --- D. Data Chunks ---
	var chunkLengthBuf [2]byte
	for len(remainingB) > 0 {
		chunkLen := common.Min(TCPChunkMaxLen, len(remainingB))

		// 1. Seal Length (2 bytes)
		binary.BigEndian.PutUint16(chunkLengthBuf[:], uint16(chunkLen))
		c.cipherWrite.Seal(buf[curr:curr], c.nonceWrite, chunkLengthBuf[:], nil)
		curr += 2 + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)

		// 2. Seal Payload
		// 注意：Payload 数据在 remainingB 中，Seal 到 buf[curr:]
		c.cipherWrite.Seal(buf[curr:curr], c.nonceWrite, remainingB[:chunkLen], nil)
		curr += chunkLen + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)

		remainingB = remainingB[chunkLen:]
	}

	// --- E. 发送 ---
	_, err = c.Conn.Write(buf[:curr])
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
