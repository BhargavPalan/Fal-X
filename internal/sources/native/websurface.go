package native

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// locRe pulls the URLs out of a sitemap's <loc> elements.
var locRe = regexp.MustCompile(`(?is)<loc>\s*(.*?)\s*</loc>`)

// maxSurfaceURLs bounds how many URLs one host's robots/sitemap may add, so a huge
// sitemap cannot flood the graph in a single Collect.
const maxSurfaceURLs = 500

// WebSurface reads the files a web host publishes about its own structure: robots.txt
// (which names the paths the owner wants hidden — often the interesting ones),
// sitemap.xml (the owner's own URL inventory) and security.txt (the disclosure
// contact). It is active: it fetches from the host.
type WebSurface struct {
	Client Doer
}

// NewWebSurface returns a web-surface source with a bounded client.
func NewWebSurface() *WebSurface {
	return &WebSurface{Client: &http.Client{Timeout: 10 * time.Second}}
}

// Capability marks the source active, consuming a host and producing URLs and emails.
func (w *WebSurface) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/websurface",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{graph.TypeURL, graph.TypeEmail},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; it uses the standard library.
func (w *WebSurface) Available(sources.Env) bool { return true }

// Collect fetches the three published files. A host serving none of them is ordinary.
func (w *WebSurface) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	host := in.Key
	self := sink.Entity(graph.TypeHost, host, host)
	added := 0

	if body := w.fetch(ctx, host, "/robots.txt"); len(body) > 0 {
		w.parseRobots(string(body), host, self, sink, &added)
	}
	if body := w.fetch(ctx, host, "/sitemap.xml"); len(body) > 0 {
		for _, m := range locRe.FindAllStringSubmatch(string(body), -1) {
			w.addURL(strings.TrimSpace(m[1]), sink, &added)
		}
	}
	for _, p := range []string{"/.well-known/security.txt", "/security.txt"} {
		if body := w.fetch(ctx, host, p); len(body) > 0 {
			w.parseSecurityTxt(string(body), self, sink)
			break
		}
	}
	return nil
}

// fetch gets a path over HTTPS, falling back to HTTP, and returns the body or nil.
// The host key is DNS-constrained upstream, so it is safe in the URL.
func (w *WebSurface) fetch(ctx context.Context, host, path string) []byte {
	for _, scheme := range []string{"https://", "http://"} {
		if body, err := getBody(ctx, w.Client, scheme+host+path, 1); err == nil && len(body) > 0 {
			return body
		}
	}
	return nil
}

// parseRobots records each disallowed path as host evidence and emits the concrete
// paths and declared sitemaps as URLs.
func (w *WebSurface) parseRobots(body, host string, self graph.Ref, sink sources.Sink, added *int) {
	base := "https://" + host
	for line := range strings.SplitSeq(body, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "disallow", "allow":
			if val == "" || val == "/" {
				continue
			}
			sink.Fact(self, "robots_path", val, 0.8)
			// A path with a wildcard is a pattern, not a fetchable URL, so only concrete
			// paths become URL entities.
			if strings.HasPrefix(val, "/") && !strings.ContainsAny(val, "*? ") {
				w.addURL(base+val, sink, added)
			}
		case "sitemap":
			w.addURL(val, sink, added)
		}
	}
}

// parseSecurityTxt records the host as publishing a disclosure policy and harvests the
// contact addresses.
func (w *WebSurface) parseSecurityTxt(body string, self graph.Ref, sink sources.Sink) {
	sink.Fact(self, "security_txt", "present", 1.0)
	for line := range strings.SplitSeq(body, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "contact") {
			continue
		}
		val = strings.TrimSpace(val)
		addr := strings.ToLower(strings.TrimPrefix(val, "mailto:"))
		if emailRe.MatchString(addr) && !strings.Contains(addr, "/") {
			sink.Entity(graph.TypeEmail, addr, addr)
			sink.Fact(self, "security_contact", addr, 0.9)
		} else if val != "" {
			sink.Fact(self, "security_contact", val, 0.8)
		}
	}
}

// addURL emits a URL entity if it parses and the per-Collect cap has room.
func (w *WebSurface) addURL(raw string, sink sources.Sink, added *int) {
	if *added >= maxSurfaceURLs || raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return
	}
	sink.Entity(graph.TypeURL, raw, raw)
	*added++
	if h := trimName(u.Hostname()); isHostname(h) {
		sink.Entity(graph.TypeHost, h, h)
	}
}
