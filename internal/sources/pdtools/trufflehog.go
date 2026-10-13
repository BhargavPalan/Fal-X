package pdtools

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Trufflehog wraps trufflehog over a discovered repository, reporting the credentials it
// finds — and, crucially, whether each one is live-verified. It pairs with the
// repository entities grep.app and GitHub search produce. The secret value itself is
// never stored; only its detector, location and verification state. It is heavy and
// active, so it runs only in full mode and only when the binary is installed.
type Trufflehog struct{ Runner Runner }

// NewTrufflehog returns a trufflehog adapter.
func NewTrufflehog() *Trufflehog { return &Trufflehog{Runner: defaultRunner} }

// Capability marks it heavy and active, consuming a repository.
func (t *Trufflehog) Capability() sources.Capability {
	return sources.Capability{
		Name:     "pdtools/trufflehog",
		Consumes: []graph.EntityType{graph.TypeRepository},
		Produces: []graph.EntityType{graph.TypeCredential, graph.TypeFinding},
		Passive:  false,
		Heavy:    true,
		Cost:     3,
	}
}

// Available reports whether trufflehog is on PATH.
func (t *Trufflehog) Available(sources.Env) bool { return available("trufflehog") }

// thLine is the subset of trufflehog's JSON output the adapter reads.
type thLine struct {
	DetectorName string `json:"DetectorName"`
	Verified     bool   `json:"Verified"`
	SourceMeta   struct {
		Data struct {
			Git struct {
				File string `json:"file"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

// Collect clones and scans the repository, recording each secret by detector and
// verification state without storing its value.
func (t *Trufflehog) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	// The repository key is "github.com/owner/repo"; build the clone URL from it.
	repoURL := "https://" + strings.TrimPrefix(in.Key, "https://")
	if !safeArg(repoURL) {
		return nil
	}
	out, err := t.Runner.Run(ctx, "trufflehog", []string{"git", repoURL, "--json", "--no-update"}, nil)
	if err != nil {
		return err
	}
	self := sink.Entity(graph.TypeRepository, in.Key, in.Key)
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r thLine
		if json.Unmarshal([]byte(line), &r) != nil || r.DetectorName == "" {
			continue
		}
		file := strings.TrimSpace(r.SourceMeta.Data.Git.File)
		key := "secret:" + r.DetectorName + "@" + in.Key + ":" + file
		cred := sink.Entity(graph.TypeCredential, key, r.DetectorName)
		sink.Edge(self, cred, graph.RelLeaks, 0.9)
		if r.Verified {
			sink.Fact(self, "finding", "high verified-secret "+r.DetectorName, 0.95)
		} else {
			sink.Fact(self, "finding", "medium unverified-secret "+r.DetectorName, 0.6)
		}
	}
	return nil
}
