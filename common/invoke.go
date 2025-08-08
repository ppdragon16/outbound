package common

import (
	"context"
)

func Invoke[R any](ctx context.Context, fn func() (R, error), cb func()) (res R, err error) {
	resChan := make(chan struct{})

	go func() {
		res, err = fn()
		resChan <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-resChan:
	}

	if err != nil && cb != nil {
		cb()
	}

	return
}
