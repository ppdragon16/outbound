package tls

import (
	"testing"
	"time"
)

// TestSpiderHarvestReleasesLockOnPanic pins the panic-safety of the spider's
// maps lock: a panic inside the locked region (here a write to a nil path map,
// which the harvest does) must not leave the mutex held, because the recover
// that contains such a panic sits outside the critical section -- a lock left
// held would outlive the recovered panic and wedge every later spider access.
// (Port of olicesx/outbound 2f4eba2's lock discipline.)
func TestSpiderHarvestReleasesLockOnPanic(t *testing.T) {
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		// nil paths: the harvest writes into it, which panics while the lock
		// is held.
		_ = spiderHarvest(nil, []byte("https://example.com"), []byte(`<a href="/next">`))
	}()
	if !panicked {
		t.Skip("the harvested body no longer panics on a nil path map; the lock assertion below would be vacuous")
	}

	done := make(chan struct{})
	go func() {
		maps.Lock()
		maps.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		maps.Unlock() // best effort so later tests are not wedged by this one
		t.Fatal("a panic inside the locked region left the maps mutex held")
	}
}
