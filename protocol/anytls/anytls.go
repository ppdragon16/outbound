package anytls

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

// Feature1 carries AnyTLS-specific configuration through Header.Feature1.
type Feature1 struct {
	IdleSessionCheckInterval time.Duration
	IdleSessionTimeout       time.Duration
	MinIdleSession           int
}

const ( // cmds
	cmdWaste               = iota // Paddings
	cmdSYN                        // stream open
	cmdPSH                        // data push
	cmdFIN                        // stream close, a.k.a EOF mark
	cmdSettings                   // Settings (Client send to Server)
	cmdAlert                      // Alert
	cmdUpdatePaddingScheme        // update padding scheme
	// Since version 2
	cmdSYNACK         // Server reports to the client that the stream has been opened
	cmdHeartRequest   // Keep alive command
	cmdHeartResponse  // Keep alive command
	cmdServerSettings // Settings (Server send to client)
)

const (
	headerOverHeadSize = 1 + 4 + 2
	// maxFramePayloadSize caps a single frame's data so the encoded frame
	// (headerOverHeadSize + data) stays within pool's largest bucket (65536).
	// At math.MaxUint16 a frame encodes to 65542 bytes, overflowing the pool
	// and forcing a heap allocation per write — a ~67x slowdown near 64KB.
	// The receiver reads by the wire Length field, so the sender's chunking
	// choice does not affect protocol compatibility.
	maxFramePayloadSize = 32768
	maxUDPPayloadSize   = math.MaxUint16
)

// frame defines a packet from or to be multiplexed into a single connection
type frame struct {
	cmd  byte   // 1
	sid  uint32 // 4
	data []byte // 2 + len(data)
}

func newFrame(cmd byte, sid uint32) frame {
	return frame{cmd: cmd, sid: sid}
}

type rawHeader [headerOverHeadSize]byte

func (h rawHeader) Cmd() byte {
	return h[0]
}

func (h rawHeader) StreamID() uint32 {
	return binary.BigEndian.Uint32(h[1:])
}

func (h rawHeader) Length() uint16 {
	return binary.BigEndian.Uint16(h[5:])
}

func writeFrame(session *session, frame frame) (int, error) {
	return writeFrameWithDeadline(session, frame, time.Time{})
}

func writeFrameWithDeadline(session *session, frame frame, deadline time.Time) (int, error) {
	size, err := encodedFrameSize(frame)
	if err != nil {
		return 0, err
	}
	buffer := pool.GetBuffer(size)
	defer pool.PutBuffer(buffer)

	encodeFrame(buffer, frame)
	if _, err := session.writeConnWithDeadline(buffer, deadline); err != nil {
		return 0, err
	}
	return len(frame.data), nil
}

// writeFrames encodes multiple frames into one contiguous pool buffer and
// writes them in a single conn.Write call. This batches settings+SYN+PSH
// into one TLS record on the first stream, saving an RTT.
func writeFrames(session *session, frames ...frame) (int, error) {
	totalSize := 0
	totalData := 0
	for _, frame := range frames {
		size, err := encodedFrameSize(frame)
		if err != nil {
			return 0, err
		}
		totalSize += size
		totalData += len(frame.data)
	}

	buffer := pool.GetBuffer(totalSize)
	defer pool.PutBuffer(buffer)
	offset := 0
	for _, frame := range frames {
		offset += encodeFrame(buffer[offset:], frame)
	}
	if _, err := session.writeConn(buffer); err != nil {
		return 0, err
	}
	return totalData, nil
}

func encodedFrameSize(frame frame) (int, error) {
	dataLen := len(frame.data)
	if dataLen > maxFramePayloadSize {
		return 0, fmt.Errorf("anytls frame payload too large: %d > %d", dataLen, maxFramePayloadSize)
	}
	return headerOverHeadSize + dataLen, nil
}

// encodeFrame writes the frame header and copies payload into dst.
// Returns the number of bytes written (always headerOverHeadSize + dataLen).
func encodeFrame(dst []byte, frame frame) int {
	dataLen := len(frame.data)
	dst[0] = frame.cmd
	binary.BigEndian.PutUint32(dst[1:], frame.sid)
	binary.BigEndian.PutUint16(dst[5:], uint16(dataLen))
	copy(dst[headerOverHeadSize:], frame.data)
	return headerOverHeadSize + dataLen
}

// writeDataFrames splits a large payload into chunks respecting
// maxFramePayloadSize, sending each as a PSH frame.
func writeDataFrames(session *session, sid uint32, data []byte, deadline time.Time) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	written := 0
	for written < len(data) {
		end := written + maxFramePayloadSize
		if end > len(data) {
			end = len(data)
		}
		frame := newFrame(cmdPSH, sid)
		frame.data = data[written:end]
		if _, err := writeFrameWithDeadline(session, frame, deadline); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}
