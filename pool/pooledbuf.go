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

// Read reads up to len(p) bytes into p. It returns the number of bytes
// read (0 <= n <= len(p)) and any error encountered. Implements io.Reader.
func (b *PooledBuffer) Read(p []byte) (n int, err error) {
	if b.off >= len(b.buf) {
		return 0, io.EOF
	}
	n = copy(p, b.buf[b.off:])
	b.off += n
	return n, nil
}

// Write appends p to the buffer.
func (b *PooledBuffer) Write(p []byte) (int, error) {
	m, ok := b.tryGrowByReslice(len(p))
	if !ok {
		m = b.grow(len(p))
	}
	return copy(b.buf[m:], p), nil
}

// WriteByte appends a byte to the buffer.
func (b *PooledBuffer) WriteByte(c byte) error {
	m, ok := b.tryGrowByReslice(1)
	if !ok {
		m = b.grow(1)
	}
	b.buf[m] = c
	return nil
}

// WriteString appends s to the buffer.
func (b *PooledBuffer) WriteString(s string) (int, error) {
	m, ok := b.tryGrowByReslice(len(s))
	if !ok {
		m = b.grow(len(s))
	}
	return copy(b.buf[m:], s), nil
}

// String returns the unread portion as a string.
func (b *PooledBuffer) String() string {
	return string(b.buf[b.off:])
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

// ReadFromN reads n bytes from r, or until EOF is reached.
func (b *PooledBuffer) ReadFromN(r io.Reader, n int) error {
	needs := n - b.Len()
	if needs <= 0 {
		return nil
	}
	m := b.grow(needs + minRead)
	remaining := needs
	c := cap(b.buf)
	copied := 0
	for remaining > 0 {
		nn, err := r.Read(b.buf[m+copied : c])
		if nn > 0 {
			copied += nn
			remaining -= nn
		}
		if err != nil {
			b.buf = b.buf[:m+copied]
			return err
		}
	}
	b.buf = b.buf[:m+copied]
	return nil
}

// Grow ensures room for n more bytes.
func (b *PooledBuffer) Grow(n int) {
	if n < 0 {
		panic("PooledBuffer.Grow: negative count")
	}
	m := b.grow(n)
	b.buf = b.buf[:m]
}

// Detach extracts the backing array and transfers ownership to the caller.
// The buffer is left empty and ready for reuse. Unlike Reset, the backing
// array is NOT returned to the pool — the caller is responsible for it.
func (b *PooledBuffer) Detach() []byte {
	data := b.buf[b.off:]
	b.buf = nil
	b.off = 0
	return data
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
		// Soft reset: reuse the backing array.
		b.buf = b.buf[:0]
		b.off = 0
	}
	// Compact unread bytes to front. This frees capacity consumed by
	// the read offset, so tryGrowByReslice succeeds more often and
	// reallocations stay within the 64KB pool limit.
	if b.off > 0 {
		copy(b.buf, b.buf[b.off:])
		b.buf = b.buf[:m]
		b.off = 0
	}
	if i, ok := b.tryGrowByReslice(n); ok {
		return i
	}
	// Reallocation needed.
	c := cap(b.buf)
	newCap := 2*c + n
	// If the total fits within the pool max, cap at maxsize to avoid
	// direct make() for buffers just over the 64KB threshold.
	if newCap > maxsize && m+n <= maxsize {
		newCap = maxsize
	}
	newBuf := GetBuffer(newCap)
	copy(newBuf, b.buf)
	if c > 0 {
		PutBuffer(b.buf)
	}
	b.buf = newBuf[:m+n]
	return m
}
