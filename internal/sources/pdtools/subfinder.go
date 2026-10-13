package pdtools

import (
	"context"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Subfinder wraps ProjectDiscovery's subfinder, which aggregates passive subdomain
// sources (dozens of them, several needing keys subfinder reads from its own config).
// It is passive and runs only when the binary is installed.
type Subfinder struct{ Runner Runner }

// NewSubfinder returns a subfinder adapter using the default runner.
func NewSubfinder() *Subfinder { return &Subfinder{Runner: defaultRunner} }

// Capability marks it passive, consuming a domain and producing hosts.
func (s *Subfinder) Capability() sources.Capability {
	return sources.Capability{
		Name:     "pdtools/subfinder",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeHost},
		Passive:  true,
		Cost:     1,
	}
}

// Available reports whether subfinder is on PATH.
func (s *Subfinder) Available(sources.Env) bool { return available("subfinder") }

// Collect runs subfinder and emits each subdomain as a host.
func (s *Subfinder) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	if !safeArg(in.Key) {
		return nil
	}
	out, err := s.Runner.Run(ctx, "subfinder", []string{"-silent", "-d", in.Key}, nil)
	if err != nil {
		return err
	}
	self := sink.Entity(graph.TypeDomain, in.Key, in.Key)
	seen := map[string]struct{}{}
	for line := range strings.SplitSeq(string(out), "\n") {
		name := trimName(line)
		if !validHost(name) {
			continue
		}
		if name != in.Key && !strings.HasSuffix(name, "."+in.Key) {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		h := sink.Entity(graph.TypeHost, name, name)
		sink.Edge(h, self, graph.RelSubdomainOf, 1.0)
	}
	return nil
}
