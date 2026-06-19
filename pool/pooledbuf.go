package pool

import "io"

// PooledBuffer is a bytes.Buffer replacement that uses GetBuffer/PutBuffer
// for internal buffer allocation. It mirrors bytes.Buffer's internal grow
// logic exactly so that ReadFrom produces identical read patterns.
type PooledBuffer struct {
	buf []byte
	off int
}

const minRead = 512

// NewPooledBuffer returns an initialized PooledBuffer.
func NewPooledBuffer() *PooledBuffer { return &PooledBuffer{} }

// Len returns the number of unread bytes.
func (b *PooledBuffer) Len() int { return len(b.buf) - b.off }

// Bytes returns the unread portion.
func (b *PooledBuffer) Bytes() []byte { return b.buf[b.off:] }

// Next returns the next n bytes, advancing read position.
func (b *PooledBuffer) Next(n int) []byte {
	m := b.Len()
	if n > m {
		n = m
	}
	data := b.buf[b.off : b.off+n]
	b.off += n
	return data
}

// Write appends p to the buffer.
func (b *PooledBuffer) Write(p []byte) (int, error) {
	m, ok := b.tryGrowByReslice(len(p))
	if !ok {
		m = b.grow(len(p))
	}
	return copy(b.buf[m:], p), nil
}

// ReadFrom reads data from r until EOF.
func (b *PooledBuffer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		i := b.grow(minRead)
		b.buf = b.buf[:i]
		m, e := r.Read(b.buf[i:cap(b.buf)])
		if m < 0 {
			panic("PooledBuffer.ReadFrom: reader returned negative count")
		}
		b.buf = b.buf[:i+m]
		n += int64(m)
		if e == io.EOF {
			return n, nil
		}
		if e != nil {
			return n, e
		}
	}
}

// Grow ensures room for n more bytes.
func (b *PooledBuffer) Grow(n int) {
	if n < 0 {
		panic("PooledBuffer.Grow: negative count")
	}
	m := b.grow(n)
	b.buf = b.buf[:m]
}

// Reset discards all data.
func (b *PooledBuffer) Reset() {
	if cap(b.buf) > 0 {
		PutBuffer(b.buf)
	}
	b.buf = nil
	b.off = 0
}

func (b *PooledBuffer) tryGrowByReslice(n int) (int, bool) {
	if l := len(b.buf); n <= cap(b.buf)-l {
		b.buf = b.buf[:l+n]
		return l, true
	}
	return 0, false
}

func (b *PooledBuffer) grow(n int) int {
	m := b.Len()
	if m == 0 && b.off != 0 {
		b.Reset()
	}
	if i, ok := b.tryGrowByReslice(n); ok {
		return i
	}
	c := cap(b.buf)
	if n <= c/2-m {
		copy(b.buf, b.buf[b.off:])
	} else {
		newCap := 2*c + n
		newBuf := GetBuffer(newCap)
		copy(newBuf, b.buf[b.off:])
		if c > 0 {
			PutBuffer(b.buf)
		}
		b.buf = newBuf[:m+n]
		b.off = 0
		return m
	}
	b.buf = b.buf[:m+n]
	b.off = 0
	return m
}
