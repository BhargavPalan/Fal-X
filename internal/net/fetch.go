package net

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// HTTPDoer is the subset of http.Client this package uses.
//
// Narrowing it keeps the gate substitutable in a test with a server that
// records whether it was contacted at all.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Limits bounds a single fetch. They exist so a run cannot be talked into
// downloading an unbounded body or waiting on an unbounded redirect chain.
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

// defaultClient builds a client that does not follow redirects.
//
// Following is done by hand in followRedirects so the scope gate is applied to
// every hop. A client-level redirect follow would hand the next request to
// another host with no gate in front of it, which is the single most likely way
// for an out-of-scope host to be contacted.
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

// newLocalClient returns a client with no timeout, for tests against a local
// server. A zero timeout would hang the suite rather than fail it.
func newLocalClient() *http.Client {
	return &http.Client{
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

// Get performs a scope-gated GET, following redirects one hop at a time with
// the gate applied to every hop.
//
// Each hop is authorized before the request is issued. A redirect is attacker-
// controlled input, so treating the first URL as the authorization covers only
// the first request.
func (g *Gate) Get(rawURL string) (*Response, error) {
	return g.GetContext(context.Background(), rawURL)
}

// GetContext is Get with a caller-supplied context.
func (g *Gate) GetContext(ctx context.Context, rawURL string) (*Response, error) {
	l := DefaultLimits("dev")

	current := rawURL
	for hop := 0; ; hop++ {
		if err := g.RequireAllowed(current, ""); err != nil {
			if hop > 0 {
				g.redirect.Add(1)
				return nil, fmt.Errorf("blocked out-of-scope redirect target %s: %w", current, err)
			}
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
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

// FilterURLs keeps only the in-scope entries of in, writing them to out.
//
// This is a bulk convenience, not a second authorization decision: each entry
// is judged by the same Scope.Gate that RequireAllowed uses, so the two cannot
// disagree: there is only one implementation of the decision.
//
// The output is always created, even when nothing is kept, because a present
// empty file and a missing file mean different things to a stage manifest.
func FilterURLs(g *Gate, in, out string) error {
	entries, ok := util.ReadLines(in)
	if !ok {
		// Either the file is absent or it is empty. Both produce a present,
		// empty output so the consumer can tell "ran, matched nothing" from
		// "never got this far".
		return util.WriteLines(out, nil)
	}

	// Sort and compact before gating, rather than deduplicating with a map.
	//
	// A map of every distinct entry is the single largest allocation here, and a
	// crawler list can be millions of lines. Sorting first costs one allocation
	// and lets the duplicates fall out of an adjacent comparison, so the map is
	// not needed at all.
	//
	// Gating after the compaction also means the decision runs once per distinct
	// entry rather than once per line, which matters because the gate is the
	// expensive part.
	sort.Strings(entries)
	entries = compactSorted(entries)

	// The surviving entries keep the order they already had, so the output is
	// sorted and a second sort is unnecessary.
	kept := make([]string, 0, len(entries))
	for _, e := range entries {
		if !g.Scope().Gate(e, "") {
			continue
		}
		kept = append(kept, e)
	}

	return util.WriteLines(out, kept)
}

// compactSorted removes adjacent duplicates from a sorted slice, in place.
func compactSorted(in []string) []string {
	if len(in) < 2 {
		return in
	}
	n := 0
	for i := 1; i < len(in); i++ {
		if in[i] == in[n] {
			continue
		}
		n++
		in[n] = in[i]
	}
	// Clear the tail so the discarded strings can be collected. A large list
	// would otherwise stay reachable through the backing array.
	for i := n + 1; i < len(in); i++ {
		in[i] = ""
	}
	return in[:n+1]
}
