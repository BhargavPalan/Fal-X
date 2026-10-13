package native

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// maxBody bounds a response read, so a hostile or huge endpoint cannot exhaust
// memory. Certificate-transparency results for a large estate can be tens of MB,
// so the cap is generous.
const maxBody = 64 << 20

// Doer is the subset of *http.Client the native HTTP sources need, so they can be
// tested against an httptest server or a fake.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// readBounded reads at most n bytes from r, discarding the rest, so a hostile or large
// response cannot exhaust memory.
func readBounded(r io.Reader, n int64) []byte {
	b, _ := io.ReadAll(io.LimitReader(r, n))
	return b
}

// parseWebURL parses a value and reports whether it is a usable http(s) URL.
func parseWebURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, false
	}
	return u, true
}

// httpGet issues one GET and returns the body (bounded by maxBody) and the status.
func httpGet(ctx context.Context, client Doer, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "fal-x")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return body, resp.StatusCode, err
}

// getBody issues a GET, retrying transient failures (a transport error or a 5xx)
// with a short linear backoff. Third-party endpoints like crt.sh return 502 under
// load often enough that one attempt is unreliable. A 4xx is returned immediately,
// since retrying it would not help.
func getBody(ctx context.Context, client Doer, url string, attempts int) ([]byte, error) {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(i) * 500 * time.Millisecond):
			}
		}
		body, status, err := httpGet(ctx, client, url)
		switch {
		case err != nil:
			lastErr = err
		case status == http.StatusOK:
			return body, nil
		case status >= 500:
			lastErr = fmt.Errorf("GET %s: status %d", url, status)
		default:
			return nil, fmt.Errorf("GET %s: status %d", url, status)
		}
	}
	return nil, lastErr
}
