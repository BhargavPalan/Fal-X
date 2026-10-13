package verify

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// maxVerifyBody caps how much of a response the checker reads: enough to find a file's
// signature, never the whole file.
const maxVerifyBody = 64 << 10

// NewHTTPChecker returns a Checker backed by the system resolver and a bounded HTTP
// client. It is the real checker the command uses.
func NewHTTPChecker() Checker {
	return &httpChecker{
		client:   &http.Client{Timeout: 10 * time.Second},
		resolver: net.DefaultResolver,
	}
}

type httpChecker struct {
	client   *http.Client
	resolver *net.Resolver
}

// Get fetches a URL read-only, returning a bounded body, the status, and reached=false
// when nothing answered.
func (c *httpChecker) Get(ctx context.Context, rawURL string) ([]byte, int, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, false
	}
	req.Header.Set("User-Agent", "fal-x")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxVerifyBody))
	return body, resp.StatusCode, true
}

// Resolves reports whether a host name resolves, treating a clean NXDOMAIN as a
// definite "no" (false, nil) and any other failure as an error.
func (c *httpChecker) Resolves(ctx context.Context, host string) (bool, error) {
	_, err := c.resolver.LookupHost(ctx, host)
	if err == nil {
		return true, nil
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return false, nil // a clean NXDOMAIN is a definite "does not resolve"
	}
	return false, err
}
