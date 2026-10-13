package pdtools

import (
	"context"
	"net/url"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Katana wraps ProjectDiscovery's katana, a crawler that also parses JavaScript for
// endpoints the HTML never links. It is heavy and active, so it runs only in full mode
// and only when the binary is installed.
type Katana struct {
	Runner Runner
	Depth  string
}

// NewKatana returns a katana adapter crawling to depth 2.
func NewKatana() *Katana { return &Katana{Runner: defaultRunner, Depth: "2"} }

// Capability marks it heavy and active, consuming a URL and producing URLs and
// endpoints.
func (k *Katana) Capability() sources.Capability {
	return sources.Capability{
		Name:     "pdtools/katana",
		Consumes: []graph.EntityType{graph.TypeURL},
		Produces: []graph.EntityType{graph.TypeURL, graph.TypeEndpoint},
		Passive:  false,
		Heavy:    true,
		Cost:     2,
	}
}

// Available reports whether katana is on PATH.
func (k *Katana) Available(sources.Env) bool { return available("katana") }

// maxKatanaURLs bounds how many URLs one crawl contributes.
const maxKatanaURLs = 3000

// Collect crawls from the URL (JavaScript parsing on) and emits the URLs it finds.
func (k *Katana) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	if !safeArg(in.Key) {
		return nil
	}
	depth := k.Depth
	if depth == "" {
		depth = "2"
	}
	out, err := k.Runner.Run(ctx, "katana", []string{"-silent", "-jc", "-d", depth, "-u", in.Key}, nil)
	if err != nil {
		return err
	}
	added := 0
	seen := map[string]struct{}{}
	for line := range strings.SplitSeq(string(out), "\n") {
		raw := strings.TrimSpace(line)
		if raw == "" || added >= maxKatanaURLs {
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
		ue := sink.Entity(graph.TypeURL, raw, raw)
		added++
		// An endpoint with a path is also recorded as an endpoint under its parent URL.
		if u.Path != "" && u.Path != "/" {
			ep := sink.Entity(graph.TypeEndpoint, u.Path, u.Path)
			sink.Edge(ue, ep, graph.RelHasEndpoint, 0.8)
		}
	}
	return nil
}
