package pdtools

import (
	"context"
	"net/url"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Gau wraps gau (getallurls), which pulls a domain's URLs from Wayback, Common Crawl,
// OTX and URLScan in one call. It is passive and runs only when the binary is
// installed.
type Gau struct{ Runner Runner }

// NewGau returns a gau adapter using the default runner.
func NewGau() *Gau { return &Gau{Runner: defaultRunner} }

// Capability marks it passive, consuming a domain and producing URLs and hosts.
func (g *Gau) Capability() sources.Capability {
	return sources.Capability{
		Name:     "pdtools/gau",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeURL, graph.TypeHost},
		Passive:  true,
		Cost:     1,
	}
}

// Available reports whether gau is on PATH.
func (g *Gau) Available(sources.Env) bool { return available("gau") }

// maxGauURLs bounds how many URLs one domain contributes.
const maxGauURLs = 5000

// Collect runs gau and emits each URL, plus any in-scope host it names.
func (g *Gau) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	if !safeArg(in.Key) {
		return nil
	}
	out, err := g.Runner.Run(ctx, "gau", []string{"--subs", "--threads", "5", in.Key}, nil)
	if err != nil {
		return err
	}
	self := sink.Entity(graph.TypeDomain, in.Key, in.Key)
	added := 0
	seen := map[string]struct{}{}
	for line := range strings.SplitSeq(string(out), "\n") {
		raw := strings.TrimSpace(line)
		if raw == "" || added >= maxGauURLs {
			continue
		}
		u, perr := url.Parse(raw)
		if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		if _, dup := seen[raw]; dup {
			continue
		}
		seen[raw] = struct{}{}
		sink.Entity(graph.TypeURL, raw, raw)
		added++
		host := trimName(u.Hostname())
		if validHost(host) && (host == in.Key || strings.HasSuffix(host, "."+in.Key)) {
			h := sink.Entity(graph.TypeHost, host, host)
			sink.Edge(h, self, graph.RelSubdomainOf, 0.8)
		}
	}
	return nil
}
