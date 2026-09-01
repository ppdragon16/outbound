package meek

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
)

// httpTripperClient round-trips meek requests over a transport that is fixed
// at dialer construction: the meek URL, the TLS settings and the parent
// dialer are all per-proxy configuration, so each dialer owns one transport
// outright and no runtime cache is needed.
type httpTripperClient struct {
	url          string
	roundTripper http.RoundTripper
}

func (c *httpTripperClient) RoundTrip(ctx context.Context, req Request) (resp Response, err error) {
	connectionTagStr := base64.RawURLEncoding.EncodeToString(req.ConnectionTag)

	httpRequest, err := http.NewRequest("POST", c.url, bytes.NewReader(req.Data))
	if err != nil {
		return
	}
	httpRequest.Header.Set("X-Session-ID", connectionTagStr)

	httpResp, err := c.roundTripper.RoundTrip(httpRequest)
	if err != nil {
		return
	}
	defer httpResp.Body.Close()

	result, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return
	}
	return Response{Data: result}, err
}
