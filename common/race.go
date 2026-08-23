/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"context"
)

// Race runs dial for every candidate concurrently (happy-eyeballs) and returns
// the first success. A single unbuffered channel carries results: the first
// success read wins. Every other candidate either fails (dial must close its
// own resources on error) or succeeds-and-loses — in which case its goroutine
// self-tears-down via teardown, because once the winner returns nobody is left
// to receive from the unbuffered channel.
//
// C is the candidate type: net.Addr for the QUIC protocols, or a "host:port"
// string for the direct dialer. dial receives each candidate verbatim, so a
// caller whose candidate is already the value it dials avoids any conversion.
//
// ctx is the dial budget; the derived raceCtx lets losers know the race ended
// as soon as a winner is found, independent of when (or whether) the caller
// cancels ctx — using ctx.Done() directly would leave a loser blocked forever
// if ctx has no deadline (e.g. context.Background()).
//
// teardown is called only on a successful-but-lost result, exactly once per
// loser. It must NOT be called for the winner.
func Race[C any, T any](ctx context.Context, candidates []C, dial func(context.Context, C) (T, error), teardown func(T)) (T, error) {
	var zero T
	if len(candidates) == 0 {
		return zero, ctx.Err()
	}
	if len(candidates) == 1 {
		return dial(ctx, candidates[0])
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	type result struct {
		val T
		err error
	}
	results := make(chan result) // unbuffered: a loser with no receiver self-tears-down
	for _, c := range candidates {
		go func(c C) {
			val, err := dial(raceCtx, c)
			select {
			case results <- result{val, err}:
			case <-raceCtx.Done():
				// A winner already emerged (or the budget expired); nobody
				// will receive this result, so tear down a successful candidate.
				if err == nil {
					teardown(val)
				}
			}
		}(c)
	}

	var firstErr error
	for range candidates {
		select {
		case r := <-results:
			if r.err == nil {
				// Winner. Return immediately; defer raceCancel() unblocks the
				// remaining candidates, which self-tear-down.
				return r.val, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
		case <-ctx.Done():
			if firstErr != nil {
				return zero, firstErr
			}
			return zero, ctx.Err()
		}
	}
	if firstErr != nil {
		return zero, firstErr
	}
	return zero, ctx.Err()
}
