/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package iout

import (
	"io"

	"github.com/daeuniverse/outbound/pool"
)

// WriteFull writes all of b to w. A short write with a nil error is
// retried; a zero-length write with a nil error is treated as
// io.ErrShortWrite so the caller cannot observe a successful partial
// frame.
func WriteFull(w io.Writer, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		wn, err := w.Write(b[n:])
		n += wn
		if err != nil {
			return n, err
		}
		if wn == 0 {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}

func MultiWrite(dst io.Writer, bs ...[]byte) (int64, error) {
	var n int
	for _, b := range bs {
		n += len(b)
	}
	buf := pool.GetBuffer(n)[:0]
	defer pool.PutBuffer(buf)
	for _, b := range bs {
		buf = append(buf, b...)
	}
	n, err := dst.Write(buf)
	return int64(n), err
}
