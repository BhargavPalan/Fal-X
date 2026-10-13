package pdtools

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Fingerprintx wraps fingerprintx, which identifies the protocol behind a non-HTTP
// open port (SSH, RDP, MySQL, Redis, LDAP, SMB and the like) by its banner. It fills
// the gap the HTTP probe leaves on the many services that do not speak HTTP. It is
// active and runs only when the binary is installed.
type Fingerprintx struct{ Runner Runner }

// NewFingerprintx returns a fingerprintx adapter.
func NewFingerprintx() *Fingerprintx { return &Fingerprintx{Runner: defaultRunner} }

// Capability marks it active, consuming a service.
func (f *Fingerprintx) Capability() sources.Capability {
	return sources.Capability{
		Name:     "pdtools/fingerprintx",
		Consumes: []graph.EntityType{graph.TypeService},
		Produces: []graph.EntityType{graph.TypeService, graph.TypeTechnology},
		Passive:  false,
		Cost:     1,
	}
}

// Available reports whether fingerprintx is on PATH.
func (f *Fingerprintx) Available(sources.Env) bool { return available("fingerprintx") }

// fxLine is the subset of fingerprintx's JSON output the adapter reads.
type fxLine struct {
	Protocol string `json:"protocol"`
	Version  string `json:"version"`
	Service  string `json:"service"`
}

// Collect feeds the host:port to fingerprintx and records the protocol it detected.
func (f *Fingerprintx) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	if !safeArg(in.Key) {
		return nil
	}
	out, err := f.Runner.Run(ctx, "fingerprintx", []string{"--json"}, []byte(in.Key+"\n"))
	if err != nil {
		return err
	}
	self := sink.Entity(graph.TypeService, in.Key, in.Key)
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r fxLine
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(firstNonEmpty(r.Protocol, r.Service)))
		if proto != "" {
			sink.Fact(self, "service", proto, 0.9)
		}
		if r.Version != "" {
			sink.Fact(self, "tech", strings.TrimSpace(proto+" "+r.Version), 0.8)
		}
	}
	return nil
}

// firstNonEmpty returns a if it is non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
