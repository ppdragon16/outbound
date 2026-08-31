package iout

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// shortWriter emits at most max bytes per Write and never reports an error,
// mimicking conns (or io.Writer wrappers) that legally return short writes.
type shortWriter struct {
	max int
	n   int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	n := len(p)
	if n > w.max {
		n = w.max
	}
	w.n += n
	return n, nil
}

// zeroWriter models a writer that makes no progress while reporting success:
// treating that as success would let a caller observe a partial frame as
// complete.
type zeroWriter struct{}

func (zeroWriter) Write(p []byte) (int, error) { return 0, nil }

func TestWriteFullSingleWrite(t *testing.T) {
	var buf bytes.Buffer
	n, err := WriteFull(&buf, []byte("hello"))
	if err != nil || n != 5 || buf.String() != "hello" {
		t.Fatalf("WriteFull = (%d, %v), wrote %q", n, err, buf.String())
	}
}

func TestWriteFullRetriesShortWrites(t *testing.T) {
	w := &shortWriter{max: 2}
	n, err := WriteFull(w, []byte("abcdef"))
	if err != nil || n != 6 || w.n != 6 {
		t.Fatalf("WriteFull = (%d, %v), writer saw %d", n, err, w.n)
	}
}

func TestWriteFullZeroProgressIsShortWrite(t *testing.T) {
	want := io.ErrShortWrite
	n, err := WriteFull(zeroWriter{}, []byte("data"))
	if !errors.Is(err, want) {
		t.Fatalf("WriteFull = (%d, %v), want %v", n, err, want)
	}
}

func TestWriteFullPropagatesError(t *testing.T) {
	want := errors.New("boom")
	n, err := WriteFull(failWriter{err: want}, []byte("data"))
	if !errors.Is(err, want) || n != 0 {
		t.Fatalf("WriteFull = (%d, %v), want (0, %v)", n, err, want)
	}
}

func TestWriteFullEmptyInput(t *testing.T) {
	var buf bytes.Buffer
	n, err := WriteFull(&buf, nil)
	if err != nil || n != 0 {
		t.Fatalf("WriteFull(nil) = (%d, %v)", n, err)
	}
}

type failWriter struct{ err error }

func (w failWriter) Write(p []byte) (int, error) { return 0, w.err }
