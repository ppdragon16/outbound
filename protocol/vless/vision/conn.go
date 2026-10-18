package vision

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"

	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/pool"

	"github.com/google/uuid"
	utls "github.com/refraction-networking/utls"

	"crypto/tls"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	_ io.Writer = (*writeWrapper)(nil)
	_ io.Reader = (*readWrapper)(nil)
	// _ io.ReaderFrom = (*Conn)(nil)
	_ io.WriterTo = (*Conn)(nil)
)

type readWrapper struct {
	directRead bool
	vision     *Conn
}

func (r *readWrapper) Read(p []byte) (n int, err error) {
	if r.directRead {
		// logrus.Println("direct read")
		return r.vision.Conn.Read(p)
	}
	return r.vision.overlayConn.Read(p)
}

type writeWrapper struct {
	writeDirect bool
	vision      *Conn
}

func (w *writeWrapper) Write(p []byte) (int, error) {
	// logrus.Println("write wrapper", "w.writeDirect", w.writeDirect)
	if w.writeDirect {
		return w.vision.Conn.Write(p)
	}
	return w.vision.overlayConn.Write(p)
}

type Conn struct {
	net.Conn             // underlay conn (net.Conn/net.PacketConn)
	overlayConn net.Conn // (vless.Conn)
	userUUID    []byte

	tlsConn  net.Conn
	input    *bytes.Reader
	rawInput *bytes.Buffer

	needHandshake              bool
	packetsToFilter            int
	isTLS                      bool
	isTLS12orAbove             bool
	enableXTLS                 bool
	cipher                     uint16
	remainingServerHello       uint16
	readRemainingContent       int
	readRemainingPadding       int
	readFilterUUID             bool
	readLastCommand            byte
	writeFilterApplicationData bool
	writer                     *writeWrapper
	reader                     *readWrapper
	toWriteDirect              bool
	toReadDirect               bool

	muWrite sync.Mutex
	muRead  sync.Mutex
}

func (vc *Conn) Read(b []byte) (int, error) {
	vc.muRead.Lock()
	defer vc.muRead.Unlock()
	if vc.toReadDirect {
		return vc.reader.Read(b)
	}
	return vc.read(b)
}

// CloseWrite half-closes the write side. In direct-copy mode the FIN goes
// straight to the underlay TCP socket; otherwise it is forwarded through the
// vless overlay conn.
func (vc *Conn) CloseWrite() error {
	vc.muWrite.Lock()
	defer vc.muWrite.Unlock()
	if vc.toWriteDirect {
		if tcp, ok := vc.Conn.(*net.TCPConn); ok {
			return tcp.CloseWrite()
		}
		return nil
	}
	if vc.overlayConn == nil {
		return nil
	}
	if cw, ok := vc.overlayConn.(netproxy.CloseWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func isTCPConnUnixConn(conn any) bool {
	if _, ok := conn.(*net.TCPConn); ok {
		return true
	} else if _, ok := conn.(*net.UnixConn); ok {
		return true
	}
	return false
}

// getUnderlayTCPConnUnixConn gets the underlay TCPConn and UnixConn.
// Use it carefully!
func getUnderlayTCPConnUnixConn(conn any) (any, bool) {
	// log.Printf("Type: %T", conn)
	val := reflect.ValueOf(conn)
	for {
		if isTCPConnUnixConn(val.Interface()) {
			// log.Printf("Type: %T", val.Interface())
			return val.Interface(), true
		}
		val = reflect.Indirect(val)
		if val = val.FieldByName("Conn"); val.IsZero() {
			// log.Printf("Unexpected type: %T", val.Interface())
			return conn, false
		}
	}
}

// WriteTo implements io.WriterTo.
func (vc *Conn) WriteTo(w io.Writer) (n int64, err error) {
	if !vc.reader.directRead {
		b := pool.GetBuffer(4096)
		for {
			_n, err := vc.Read(b)
			if err != nil {
				pool.PutBuffer(b)
				return n, err
			}
			if _, err = w.Write(b[:_n]); err != nil {
				pool.PutBuffer(b)
				return n, err
			}
			n += int64(_n)
			if vc.reader.directRead {
				pool.PutBuffer(b)
				break
			}
		}
	}
	// It is safe to get the TCPConn here, because directRead == true.
	conn, _ := getUnderlayTCPConnUnixConn(vc.Conn)
	// w is *sniffing.ConnSniffer.
	// It is safe to get the TCPConn here, because we are downloading something and sniffing is over.
	w_, _ := getUnderlayTCPConnUnixConn(w)
	_n, err := conn.(io.WriterTo).WriteTo(w_.(io.Writer))
	// log.Println("Read", n, _n)
	n += _n
	return n, err
}

func (vc *Conn) read(b []byte) (int, error) {
	if vc.readRemainingContent > 0 {
		if vc.readRemainingContent < len(b) {
			b = b[:vc.readRemainingContent]
		}
		n, err := vc.reader.Read(b)
		vc.readRemainingContent -= n
		vc.FilterTLS(b[:n])
		// logrus.Println("isTLS4", vc.isTLS, vc.readRemainingContent, n)
		return n, err
	}
	if vc.readRemainingPadding > 0 {
		_, err := io.CopyN(io.Discard, vc.reader, int64(vc.readRemainingPadding))
		if err != nil {
			return 0, err
		}
		vc.readRemainingPadding = 0
	}
	n := 0
	if !vc.toReadDirect {
		switch vc.readLastCommand {
		case commandPaddingContinue:
			headerUUIDLen := 0
			if vc.readFilterUUID {
				headerUUIDLen = len(uuid.Nil)
			}
			var header []byte
			if need := headerUUIDLen + PaddingHeaderLen - len(uuid.Nil); len(b) < need {
				header = pool.GetBuffer(need)
				defer pool.PutBuffer(header)
			} else {
				header = b[:need]
			}
			// logrus.Println("read 1")
			_, err := io.ReadFull(vc.reader, header)
			if err != nil {
				return 0, err
			}
			// logrus.Println("read 2")
			if vc.readFilterUUID {
				vc.readFilterUUID = false
				if subtle.ConstantTimeCompare(vc.userUUID[:], header[:len(uuid.Nil)]) != 1 {
					id, e := uuid.FromBytes(header[:len(uuid.Nil)])
					err = fmt.Errorf("XTLS Vision server responded unknown UUID: %s: %w",
						id.String(), e)
					// logrus.Errorln(err.Error())
					return 0, err
				}
				header = header[len(uuid.Nil):]
			}
			vc.readRemainingPadding = int(binary.BigEndian.Uint16(header[3:]))
			vc.readRemainingContent = int(binary.BigEndian.Uint16(header[1:]))
			vc.readLastCommand = header[0]
			// logrus.Infof("XTLS Vision read padding: command=%d, payloadLen=%d, paddingLen=%d",
			// vc.readLastCommand, vc.readRemainingContent, vc.readRemainingPadding)
			return vc.read(b)
		case commandPaddingEnd:
			vc.toReadDirect = true
			return vc.read(b)
		case commandPaddingDirect:
			// logrus.Infoln("commandPaddingDirect")
			needReturn := false
			if vc.input != nil {
				// logrus.Infoln("commandPaddingDirect: 1", vc.input.Len())
				if vc.input.Len() > 0 {
					_n, err := vc.input.Read(b)
					if err != nil {
						return 0, err
					}
					n += _n
				}
				// logrus.Infoln("commandPaddingDirect: 1?", vc.input.Len())
				if vc.input.Len() == 0 {
					needReturn = true
					vc.input = nil
				} else { // buffer is full
					// logrus.Infoln("commandPaddingDirect: 1? full")
					return len(b), nil
				}
			}
			if vc.rawInput != nil {
				// logrus.Infoln("commandPaddingDirect: 2")
				if vc.rawInput.Len() > 0 {
					_n, err := vc.rawInput.Read(b[n:])
					if err != nil {
						return n + _n, err
					}
					n += _n
				}
				needReturn = true
				// logrus.Infoln("commandPaddingDirect: 2?", vc.rawInput.Len())
				if vc.rawInput.Len() == 0 {
					vc.rawInput = nil
				}
			}
			if vc.input == nil && vc.rawInput == nil {
				vc.toReadDirect = true
				vc.reader.directRead = true
				// logrus.Infoln("XTLS Vision direct read start")
			}
			if needReturn {
				return n, nil
			}
		default:
			err := fmt.Errorf("XTLS Vision read unknown command: %d", vc.readLastCommand)
			// log.Debugln(err.Error())
			return 0, err
		}
	}
	return vc.reader.Read(b[n:])
}

func (vc *Conn) Write(p []byte) (int, error) {
	vc.muWrite.Lock()
	defer vc.muWrite.Unlock()
	// logrus.Println("VISION CONN WRITE", hex.EncodeToString(p), "vc.writeFilterApplicationData", vc.writeFilterApplicationData)
	if vc.writeFilterApplicationData {
		err := vc.write(p)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return vc.writer.Write(p)
}

// // ReadFrom implements io.ReaderFrom.
// func (vc *Conn) ReadFrom(r io.Reader) (n int64, err error) {
// 	if !vc.writer.writeDirect {
// 		b := pool.GetBuffer(4096)
// 		for {
// 			_n, err := r.Read(b)
// 			if err != nil {
// 				pool.PutBuffer(b)
// 				return n, err
// 			}
// 			if _, err = vc.Write(b[:_n]); err != nil {
// 				pool.PutBuffer(b)
// 				return n, err
// 			}
// 			n += int64(_n)
// 			if vc.writer.writeDirect {
// 				pool.PutBuffer(b)
// 				break
// 			}
// 		}
// 	}
// 	// It is safe to get the TCPConn here, because writeDirect == true.
// 	conn, _ := getUnderlayTCPConnUnixConn(vc.Conn)
//  // Unsafe
// 	r_, _ := getUnderlayTCPConnUnixConn(r)
// 	_n, err := conn.(io.ReaderFrom).ReadFrom(r_.(io.Reader))
// 	// log.Println("Write", n, _n)
// 	n += _n
// 	return n, err
// }

func (vc *Conn) write(p []byte) (err error) {
	if vc.needHandshake {
		vc.needHandshake = false
		longPadding := len(p) == 0
		if len(p) != 0 {
			vc.FilterTLS(p)
			longPadding = vc.isTLS
		}
		if err = writePadding(vc.writer, p, commandPaddingContinue, vc.userUUID, longPadding); err != nil {
			return err
		}
		if tlsConn, ok := vc.tlsConn.(*utls.Conn); ok {
			if tlsConn.ConnectionState().Version != utls.VersionTLS13 {
				return ErrNotTLS13
			}
		} else if tlsConn, ok := vc.tlsConn.(*tls.Conn); ok {
			if tlsConn.ConnectionState().Version != tls.VersionTLS13 {
				return ErrNotTLS13
			}
		} else if utlsConn, ok := vc.tlsConn.(*utls.UConn); ok {
			if utlsConn.ConnectionState().Version != utls.VersionTLS13 {
				return ErrNotTLS13
			}
		} else {
			panic("fixme")
		}
		vc.tlsConn = nil
		return nil
	}

	if vc.writeFilterApplicationData {
		isCompleteAppData := isCompleteAppDataRecords(p)
		p, p2 := ReshapeBytes(p)
		vc.FilterTLS(p)
		if p2 != nil {
			vc.FilterTLS(p2)
		}
		if !vc.isTLS {
			// disable XTLS
			vc.writeFilterApplicationData = false
			vc.packetsToFilter = 0
			if err = writePadding(vc.writer, p, commandPaddingEnd, nil, false); err != nil {
				return err
			}
			if p2 != nil {
				_, err = iout.WriteFull(vc.writer, p2)
			}
			return err
		}

		endCommand := commandPaddingEnd
		if vc.enableXTLS {
			endCommand = commandPaddingDirect
		}
		startsWithAppData := func(b []byte) bool {
			return len(b) >= 6 && bytes.Equal(b[:3], tlsApplicationDataStart)
		}
		finishEarlyForLegacyTLS := !vc.isTLS12orAbove && vc.packetsToFilter <= 1

		if p2 == nil {
			switch {
			case isCompleteAppData && startsWithAppData(p):
				vc.toWriteDirect = vc.enableXTLS
				vc.writeFilterApplicationData = false
				err = writePadding(vc.writer, p, endCommand, nil, true)
			case finishEarlyForLegacyTLS:
				vc.writeFilterApplicationData = false
				err = writePadding(vc.writer, p, commandPaddingEnd, nil, vc.isTLS)
			default:
				err = writePadding(vc.writer, p, commandPaddingContinue, nil, vc.isTLS)
			}
			if vc.toWriteDirect {
				vc.writer.writeDirect = true
			}
		} else {
			switch {
			case isCompleteAppData && startsWithAppData(p):
				vc.toWriteDirect = vc.enableXTLS
				vc.writeFilterApplicationData = false
				if err = writePadding(vc.writer, p, commandPaddingContinue, nil, true); err != nil {
					return err
				}
				err = writePadding(vc.writer, p2, endCommand, nil, startsWithAppData(p2))
			case finishEarlyForLegacyTLS:
				vc.writeFilterApplicationData = false
				if err = writePadding(vc.writer, p, commandPaddingEnd, nil, vc.isTLS); err != nil {
					return err
				}
				_, err = iout.WriteFull(vc.writer, p2)
			default:
				if err = writePadding(vc.writer, p, commandPaddingContinue, nil, vc.isTLS); err != nil {
					return err
				}
				err = writePadding(vc.writer, p2, commandPaddingContinue, nil, vc.isTLS)
			}
			if vc.toWriteDirect {
				vc.writer.writeDirect = true
			}
		}
		return err
	}
	_, err = vc.writer.Write(p)
	return err
}

// writePadding encodes one Vision frame ([UUID][command][contentLen][paddingLen][p][padding])
// and writes it to w in a single Write call. Invariant: one Vision frame must
// be emitted with one Write so the TLS transports below emit one TLS record per
// frame instead of iout.MultiWrite splitting frames <= 4096 bytes into three
// records. (Port of kdae 0fb28f7.)
func writePadding(w io.Writer, p []byte, command byte, userUUID []byte, longPadding bool) error {
	prefix, suffix := ApplyPaddingFromPool(p, command, userUUID, longPadding)
	defer pool.PutBuffer(prefix)
	defer pool.PutBuffer(suffix)
	frame := pool.GetBuffer(len(prefix) + len(p) + len(suffix))[:0]
	defer pool.PutBuffer(frame)
	frame = append(frame, prefix...)
	frame = append(frame, p...)
	frame = append(frame, suffix...)
	_, err := w.Write(frame)
	return err
}

// isCompleteAppDataRecords reports whether b consists solely of one or more
// complete TLS ApplicationData (0x17 0x03 0x03) records. Invariant: Vision must
// never switch to Direct mode in the middle of a record.
// (Port of kdae 0fb28f7.)
func isCompleteAppDataRecords(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	for len(b) > 0 {
		if len(b) < 5 || !bytes.Equal(b[:3], tlsApplicationDataStart) {
			return false
		}
		recordLen := int(binary.BigEndian.Uint16(b[3:5]))
		if recordLen == 0 || len(b)-5 < recordLen {
			return false
		}
		b = b[5+recordLen:]
	}
	return true
}

// filterSnapshot is a consistent view of the filter state for reporting.
type filterSnapshot struct {
	packetsToFilter int
	isTLS           bool
	isTLS12orAbove  bool
	enableXTLS      bool
}

// filterSnapshot returns a consistent view of the filter state for reporting.
func (vc *Conn) filterSnapshot() filterSnapshot {
	return filterSnapshot{
		packetsToFilter: vc.packetsToFilter,
		isTLS:           vc.isTLS,
		isTLS12orAbove:  vc.isTLS12orAbove,
		enableXTLS:      vc.enableXTLS,
	}
}
