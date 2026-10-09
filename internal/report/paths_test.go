package report

import (
	"path/filepath"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/stage"
)

// TestArtifactPathsMatchTheStagePaths pins the locations this package reads against
// the ones the stages write. The report cannot import stage in production code, so
// without this a rename in stage.Paths would leave every report quietly empty.
func TestArtifactPathsMatchTheStagePaths(t *testing.T) {
	const dir = "run"
	p := stage.NewPaths(dir)
	want := map[string]string{
		"subdomains": p.Subs(),
		"resolved":   p.Resolved(),
		"addresses":  p.Addresses(),
		"open ports": p.OpenPorts(),
		"probe":      p.ProbeFile(),
		"urls":       p.URLs(),
		"endpoints":  p.Endpoints(),
		"findings":   p.Findings(),
	}
	got := map[string]string{
		"subdomains": fileSubdomains, "resolved": fileResolved, "addresses": fileAddresses,
		"open ports": fileOpenPorts, "probe": fileProbe, "urls": fileURLs,
		"endpoints": fileEndpoints, "findings": fileFindings,
	}
	for name, w := range want {
		rel, err := filepath.Rel(dir, w)
		if err != nil {
			t.Fatal(err)
		}
		if got[name] != rel {
			t.Errorf("%s: report reads %q, the stage writes %q", name, got[name], rel)
		}
	}
}
