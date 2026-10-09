package net

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/logging"
)

// HTTPDoer is the subset of http.Client this package uses, so a test can supply
// one that records whether a target was contacted at all.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Limits bounds a single fetch, so a response cannot be unbounded in size or in
// redirects.
type Limits struct {
	ConnectTimeout time.Duration
	RequestTimeout time.Duration
	MaxBodyBytes   int64
	MaxRedirects   int
	UserAgent      string
}

// DefaultLimits are the bounds a single fetch is held to.
func DefaultLimits(version string) Limits {
	return Limits{
		ConnectTimeout: 5 * time.Second,
		RequestTimeout: 20 * time.Second,
		MaxBodyBytes:   5 << 20,
		MaxRedirects:   5,
		UserAgent:      "fal-x/" + version,
	}
}

// defaultClient builds a client that does not follow redirects. GetContext follows
// them by hand so the scope gate sees every hop; a client-level follow would send
// the next request to another host with no gate in front of it.
func defaultClient(l Limits) *http.Client {
	dialer := &net.Dialer{Timeout: l.ConnectTimeout}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   l.ConnectTimeout,
			ResponseHeaderTimeout: l.RequestTimeout,
			DisableCompression:    false,
			MaxIdleConnsPerHost:   8,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (g *Gate) doer() HTTPDoer {
	if g.client != nil {
		return g.client
	}
	return defaultClient(DefaultLimits("dev"))
}

// Response is the result of a gated fetch.
type Response struct {
	StatusCode int
	FinalURL   string
	Body       []byte
	Header     http.Header
}

// GetContext performs a scope-gated GET, following redirects one hop at a time with
// the gate applied to every hop. A redirect is attacker-controlled input, so
// authorizing the first URL covers only the first request.
func (g *Gate) GetContext(ctx context.Context, rawURL string) (*Response, error) {
	l := DefaultLimits("dev")

	current := rawURL
	for hop := 0; ; hop++ {
		if err := g.RequireAllowed(current, ""); err != nil {
			if hop > 0 {
				return nil, fmt.Errorf("blocked out-of-scope redirect target %s: %w", current, err)
			}
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("build request for %s: %w", current, err)
		}
		req.Header.Set("User-Agent", l.UserAgent)
		req.Header.Set("Accept", "*/*")

		resp, err := g.doer().Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", current, err)
		}

		// A redirect: resolve it, gate the next hop, and carry on.
		if isRedirect(resp.StatusCode) {
			loc := resp.Header.Get("Location")
			resp.Body.Close()

			if loc == "" {
				return nil, fmt.Errorf("fetch %s: %d without a Location header", current, resp.StatusCode)
			}
			if hop >= l.MaxRedirects {
				logging.Warn("redirect limit (%d) reached at %s", l.MaxRedirects, current)
				return &Response{StatusCode: resp.StatusCode, FinalURL: current}, nil
			}

			next, err := resolveRedirect(current, loc)
			if err != nil {
				// A relative or unparseable target is not followed rather than
				// guessed at.
				logging.Debug("not following redirect %s from %s: %v", loc, current, err)
				return &Response{StatusCode: resp.StatusCode, FinalURL: current}, nil
			}
			current = next
			continue
		}

		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, l.MaxBodyBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", current, err)
		}
		if int64(len(body)) > l.MaxBodyBytes {
			return nil, fmt.Errorf("response from %s exceeds the %d byte limit", current, l.MaxBodyBytes)
		}

		return &Response{
			StatusCode: resp.StatusCode,
			FinalURL:   current,
			Body:       body,
			Header:     resp.Header,
		}, nil
	}
}

// isRedirect reports whether a status code carries a Location worth following.
func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// resolveRedirect turns a Location value into an absolute URL.
//
// Only http and https are accepted. A Location pointing at file:// or gopher://
// would otherwise be handed to a transport that has no business following it.
func resolveRedirect(base, location string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse base %s: %w", base, err)
	}
	ref, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("parse location %s: %w", location, err)
	}

	next := b.ResolveReference(ref)
	switch strings.ToLower(next.Scheme) {
	case "http", "https":
		return next.String(), nil
	default:
		return "", fmt.Errorf("refusing to follow a %s redirect", next.Scheme)
	}
}
