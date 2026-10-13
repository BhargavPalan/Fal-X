package pdtools

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Nuclei wraps ProjectDiscovery's nuclei, a template-driven scanner for CVEs,
// exposures, misconfigurations and takeovers. It is heavy and active, so it runs only
// in full mode and only when the binary is installed.
type Nuclei struct {
	Runner   Runner
	Severity string // comma-separated severities to run
}

// NewNuclei returns a nuclei adapter running medium and above by default.
func NewNuclei() *Nuclei {
	return &Nuclei{Runner: defaultRunner, Severity: "medium,high,critical"}
}

// Capability marks it heavy and active, consuming a URL and producing findings.
func (n *Nuclei) Capability() sources.Capability {
	return sources.Capability{
		Name:     "pdtools/nuclei",
		Consumes: []graph.EntityType{graph.TypeURL},
		Produces: []graph.EntityType{graph.TypeFinding, graph.TypeTechnology},
		Passive:  false,
		Heavy:    true,
		Cost:     3,
	}
}

// Available reports whether nuclei is on PATH.
func (n *Nuclei) Available(sources.Env) bool { return available("nuclei") }

// nucleiLine is the subset of nuclei's JSONL output the adapter reads.
type nucleiLine struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
}

// Collect runs nuclei against the URL and records each match as a finding on the URL.
func (n *Nuclei) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	if !safeArg(in.Key) {
		return nil
	}
	sev := n.Severity
	if sev == "" {
		sev = "medium,high,critical"
	}
	out, err := n.Runner.Run(ctx, "nuclei", []string{"-silent", "-jsonl", "-nc", "-u", in.Key, "-severity", sev}, nil)
	if err != nil {
		return err
	}
	self := sink.Entity(graph.TypeURL, in.Key, in.Key)
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r nucleiLine
		if json.Unmarshal([]byte(line), &r) != nil || r.TemplateID == "" {
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(r.Info.Severity))
		if sev == "" || sev == "info" || sev == "unknown" {
			sev = "low"
		}
		// The finding value is "<severity> <template> [name]", which the prioritiser
		// parses for its severity and any CVE the template id names.
		value := sev + " " + r.TemplateID
		if r.Info.Name != "" {
			value += " " + r.Info.Name
		}
		sink.Fact(self, "finding", value, 0.9)
	}
	return nil
}
