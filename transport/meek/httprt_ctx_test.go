package meek

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// ctxBlockingTripper blocks until the *request's* context is done, which is the
// only thing that can release a silent relay: RoundTrip itself has no deadline.
type ctxBlockingTripper struct{}

func (ctxBlockingTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// TestRoundTripHonoursContext pins the transport's context contract. The HTTP
// request used to be built without the caller's context, so neither the round
// trip nor the body read could be cancelled: a meek session that never answered
// wedged its caller forever, and with it the connectivity check that issued it.
func TestRoundTripHonoursContext(t *testing.T) {
	c := &httpTripperClient{
		url:          "http://meek.invalid/",
		roundTripper: ctxBlockingTripper{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := c.RoundTrip(ctx, Request{Data: []byte("ping")})
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("RoundTrip returned %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RoundTrip ignored the caller's context: the HTTP request was built without it")
	}
}
