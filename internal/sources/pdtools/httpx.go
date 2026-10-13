package pdtools

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// HTTPX wraps ProjectDiscovery's httpx for a richer web fingerprint than the native
// probe: technology detection (Wappalyzer), favicon hash, JARM, and the full response
// metadata. It is active and runs only when the binary is installed.
type HTTPX struct{ Runner Runner }

// NewHTTPX returns an httpx adapter using the default runner.
func NewHTTPX() *HTTPX { return &HTTPX{Runner: defaultRunner} }

// Capability marks it active, consuming a host.
func (h *HTTPX) Capability() sources.Capability {
	return sources.Capability{
		Name:     "pdtools/httpx",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{graph.TypeURL, graph.TypeTechnology},
		Passive:  false,
		Cost:     1,
	}
}

// Available reports whether httpx is on PATH.
func (h *HTTPX) Available(sources.Env) bool { return available("httpx") }

// httpxLine is the subset of httpx's JSON output the adapter reads.
type httpxLine struct {
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	WebServer  string   `json:"webserver"`
	Tech       []string `json:"tech"`
	Favicon    string   `json:"favicon"`
}

// Collect feeds the host to httpx on stdin and records the probe result.
func (h *HTTPX) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	if !safeArg(in.Key) {
		return nil
	}
	args := []string{"-silent", "-json", "-no-color", "-status-code", "-title",
		"-web-server", "-tech-detect", "-favicon", "-timeout", "10"}
	out, err := h.Runner.Run(ctx, "httpx", args, []byte(in.Key+"\n"))
	if err != nil {
		return err
	}
	self := sink.Entity(graph.TypeHost, in.Key, in.Key)
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r httpxLine
		if json.Unmarshal([]byte(line), &r) != nil || r.URL == "" {
			continue
		}
		u := sink.Entity(graph.TypeURL, r.URL, r.URL)
		sink.Edge(self, u, graph.RelServesURL, 1.0)
		if r.StatusCode != 0 {
			sink.Fact(u, "status", strconv.Itoa(r.StatusCode), 1.0)
		}
		if r.Title != "" {
			sink.Fact(u, "title", r.Title, 0.9)
		}
		if r.WebServer != "" {
			sink.Fact(self, "server", r.WebServer, 1.0)
		}
		if r.Favicon != "" {
			sink.Fact(self, "favicon_mmh3", r.Favicon, 0.9)
		}
		for _, t := range r.Tech {
			if t = strings.TrimSpace(t); t != "" {
				sink.Fact(self, "tech", t, 0.9)
			}
		}
	}
	return nil
}
