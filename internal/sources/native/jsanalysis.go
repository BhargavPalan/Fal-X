package native

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// jsEndpointRe lifts path-like string literals out of JavaScript: a quoted value that
// starts with "/" and reads like a route or an API path. It is deliberately narrow so
// mining a bundle does not emit every CSS class or fragment.
var jsEndpointRe = regexp.MustCompile(`["'](/[A-Za-z0-9_\-./]{2,120})["']`)

// sourceMapRe matches the sourceMappingURL comment a bundler appends, which points at the
// map that reconstructs the original, unminified source tree.
var sourceMapRe = regexp.MustCompile(`(?m)//[#@][ \t]*sourceMappingURL=(\S+)`)

// JSAnalysis mines a served JavaScript file for the endpoints it references and for an
// exposed source map. A reachable .map reconstructs the original source tree, so it is
// reported as an exposure, and its listed sources are kept as leads. It runs on a URL the
// crawl already found and only when that URL is JavaScript. It is active and heavy.
type JSAnalysis struct {
	Client Doer
}

// NewJSAnalysis returns the analyzer with a bounded client.
func NewJSAnalysis() *JSAnalysis {
	return &JSAnalysis{Client: &http.Client{Timeout: 15 * time.Second}}
}

// Capability marks it active and heavy, consuming a URL and producing endpoints, the map
// document, and an exposure finding.
func (j *JSAnalysis) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/jsanalysis",
		Consumes: []graph.EntityType{graph.TypeURL},
		Produces: []graph.EntityType{graph.TypeEndpoint, graph.TypeDocument, graph.TypeFinding},
		Passive:  false,
		Heavy:    true,
		Cost:     2,
	}
}

// Available is always true; it uses the standard library.
func (j *JSAnalysis) Available(sources.Env) bool { return true }

// maxJSBody caps how much of a script is read.
const maxJSBody = 2 << 20

// Collect fetches the URL when it is JavaScript, extracts endpoints, and checks for an
// exposed source map.
func (j *JSAnalysis) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	raw := in.Key
	u, ok := parseJSURL(raw)
	if !ok {
		return nil // only JavaScript URLs are analyzed here
	}
	body, ok := j.get(ctx, raw)
	if !ok {
		return nil
	}
	self := sink.Entity(graph.TypeURL, raw, raw)

	for _, ep := range endpointsIn(body) {
		e := sink.Entity(graph.TypeEndpoint, ep, ep)
		sink.Edge(self, e, graph.RelHasEndpoint, 0.6)
	}

	j.checkSourceMap(ctx, u, raw, body, self, sink)
	return nil
}

// checkSourceMap follows a sourceMappingURL, and when the map is reachable and lists
// original sources, records it as an exposure with those sources as evidence.
func (j *JSAnalysis) checkSourceMap(ctx context.Context, u *url.URL, raw string, body []byte, self graph.Ref, sink sources.Sink) {
	m := sourceMapRe.FindSubmatch(body)
	if m == nil {
		return
	}
	ref := strings.TrimSpace(string(m[1]))
	if ref == "" || strings.HasPrefix(ref, "data:") {
		return // an inline data: map discloses nothing extra
	}
	mapURL := resolveRef(u, ref)
	// The sourceMappingURL comes from the target's own JavaScript, so it is attacker-
	// controlled. Only follow it when it stays on the same host and scheme as the script:
	// a map pointing at another host (169.254.169.254, an internal service, a protocol-
	// relative host) would make this a blind SSRF, so it is not fetched.
	mp, err := url.Parse(mapURL)
	if err != nil || mp.Host != u.Host || (mp.Scheme != "http" && mp.Scheme != "https") {
		return
	}
	mapBody, ok := j.get(ctx, mapURL)
	if !ok {
		return
	}
	srcs := sourceMapSources(mapBody)
	if len(srcs) == 0 {
		return
	}
	sink.Entity(graph.TypeDocument, mapURL, mapURL)
	sink.Fact(self, "finding", "medium exposed-sourcemap", 0.8)
	sink.Fact(self, "exposure", "exposed_sourcemap", 0.8)
	for i, s := range srcs {
		if i >= 50 { // keep the evidence bounded
			break
		}
		sink.Fact(self, "sourcemap_source", s, 0.7)
	}
}

// get fetches a URL and returns a bounded body, or ok=false on any error or non-200.
func (j *JSAnalysis) get(ctx context.Context, raw string) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", "fal-x")
	resp, err := j.Client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxJSBody))
	return body, true
}

// endpointsIn returns the distinct path-like endpoints referenced in a script, capped so
// one huge bundle cannot flood the graph.
func endpointsIn(body []byte) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range jsEndpointRe.FindAllSubmatch(body, -1) {
		p := string(m[1])
		if p == "//" || strings.HasPrefix(p, "//") { // "//cdn..." is a protocol-relative host, not a path
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
		if len(out) >= 100 {
			break
		}
	}
	return out
}

// sourceMapSources parses a source map and returns the original source paths it lists.
func sourceMapSources(body []byte) []string {
	var m struct {
		Sources []string `json:"sources"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	return m.Sources
}

// parseJSURL parses a URL and reports whether it names a JavaScript file, returning the
// parsed URL for resolving a relative source-map reference against it.
func parseJSURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, false
	}
	return u, strings.HasSuffix(strings.ToLower(u.Path), ".js")
}

// resolveRef resolves a sourceMappingURL reference (absolute, root-relative or relative)
// against the script's own URL.
func resolveRef(base *url.URL, ref string) string {
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(r).String()
}
