// Package stage holds the reconnaissance pipeline stages.
//
// A stage is a plain function that reads its inputs from files, does one thing,
// and writes its outputs to files. It never contacts anything itself: network
// access goes through the gate, and external binaries go through the tool
// runner.
//
// The pipeline order is significant and is enforced by Run:
//
//	roots -> subs -> resolve -> {ports || http} -> {content || scan}
//
// The two concurrent pairs are real. A stage in a concurrent pair must not
// assume its peer's output exists.
package stage

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/cli"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/net"
	"github.com/BhargavPalan/Fal-X/internal/run"
	"github.com/BhargavPalan/Fal-X/internal/tools"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// Paths are the per-stage directories and the files inside them.
//
// The directory fields carry a Dir suffix and the file accessors are methods,
// because a stage directory and the list of hosts in it are different things
// and calling both "Roots" is how one gets used where the other was meant.
type Paths struct {
	Dir        string
	RootsDir   string
	SubsDir    string
	ResolveDir string
	PortsDir   string
	HTTPDir    string
	ContentDir string
	ScanDir    string
	LogsDir    string
}

// NewPaths derives the stage directories for a run directory.
//
// The numbered prefixes keep the stages in pipeline order when someone lists the
// directory, which is the only way to read a run by hand.
func NewPaths(dir string) Paths {
	return Paths{
		Dir:        dir,
		RootsDir:   filepath.Join(dir, "1-roots"),
		SubsDir:    filepath.Join(dir, "2-subs"),
		ResolveDir: filepath.Join(dir, "3-resolve"),
		PortsDir:   filepath.Join(dir, "4-ports"),
		HTTPDir:    filepath.Join(dir, "5-http"),
		ContentDir: filepath.Join(dir, "6-content"),
		ScanDir:    filepath.Join(dir, "7-scan"),
		LogsDir:    filepath.Join(dir, "logs"),
	}
}

// Ensure creates every stage directory.
func (p Paths) Ensure() error {
	for _, d := range []string{
		p.RootsDir, p.SubsDir, p.ResolveDir, p.PortsDir,
		p.HTTPDir, p.ContentDir, p.ScanDir, p.LogsDir,
	} {
		if err := util.TruncateFile(filepath.Join(d, ".keep")); err != nil {
			return fmt.Errorf("stage: create %s: %w", d, err)
		}
	}
	return nil
}

// TargetsFile is the resolved-target list, shared by the IP-mode pipeline.
func (p Paths) TargetsFile() string { return filepath.Join(p.ResolveDir, "targets.txt") }

// NetblocksFile is the in-scope subset of an ASN's announced prefixes.
func (p Paths) NetblocksFile() string { return filepath.Join(p.ResolveDir, "netblocks.txt") }

// Roots is the root-domain list.
func (p Paths) Roots() string { return filepath.Join(p.RootsDir, "roots.txt") }

// Candidates is the subdomain candidate list.
func (p Paths) Candidates() string { return filepath.Join(p.SubsDir, "candidates.txt") }

// Subs is the enumerated in-scope subdomain list.
func (p Paths) Subs() string { return filepath.Join(p.SubsDir, "subdomains.txt") }

// Rejected is the out-of-scope discovery list. Those names are kept rather than
// discarded: an out-of-scope subdomain under an in-scope root is a real finding
// about the estate.
func (p Paths) Rejected() string { return filepath.Join(p.SubsDir, "out-of-scope.txt") }

// Resolved is the verified live host list.
func (p Paths) Resolved() string { return filepath.Join(p.ResolveDir, "resolved.txt") }

// Addresses is the extracted A and AAAA list.
func (p Paths) Addresses() string { return filepath.Join(p.ResolveDir, "ips.txt") }

// Records is the DNS record dump.
func (p Paths) Records() string { return filepath.Join(p.ResolveDir, "dns.txt") }

// HostPorts is the host:port list from the port stage.
func (p Paths) HostPorts() string { return filepath.Join(p.PortsDir, "hosts.txt") }

// OpenPorts is the list of open services.
func (p Paths) OpenPorts() string { return filepath.Join(p.PortsDir, "open.txt") }

// HTTPHosts is the probed host list consumed by content and scan.
func (p Paths) HTTPHosts() string { return filepath.Join(p.HTTPDir, "http.txt") }

// ProbeFile is the raw probe output.
func (p Paths) ProbeFile() string { return filepath.Join(p.HTTPDir, "probe.json") }

// Findings is the template-scan output.
func (p Paths) Findings() string { return filepath.Join(p.ScanDir, "findings.json") }

// URLs is the crawled and historical URL list.
func (p Paths) URLs() string { return filepath.Join(p.ContentDir, "urls.txt") }

// Endpoints is the discovered endpoint list.
func (p Paths) Endpoints() string { return filepath.Join(p.ContentDir, "endpoints.txt") }

// Env is everything a stage needs.
type Env struct {
	Run   *run.Run
	Gate  *net.Gate
	Tools tools.Runner
	Opts  *cli.Options
	Paths Paths
}

// Stage is one pipeline step.
type Stage struct {
	Name string
	Fn   func(ctx context.Context, e *Env) error
	// NeedsTool names a binary the stage cannot work without. The pipeline
	// reports it as missing rather than failing obscurely mid-run.
	NeedsTool string
	// Stage lists the tools the stage uses, for the missing-tools report.
	Tools []string
}

// Stages is the pipeline in execution order.
var Stages = []Stage{
	// Tools lists what a stage cannot run without. A stage whose tools are all
	// absent is skipped, not failed: the operator installed what they wanted,
	// and reporting that as an error makes a working setup look broken.
	//
	// Optional tools are deliberately absent from these lists and are handled
	// inside the stage, which degrades and records a note. amass only runs under
	// --deep, puredns under --brute, and the whole content stage is katana, gau
	// and ffuf, all of which are optional refinements.
	{Name: "targets", Fn: Targets, Tools: nil},
	{Name: "roots", Fn: Roots, Tools: []string{"subfinder"}},
	{Name: "subs", Fn: Subs, Tools: []string{"subfinder"}},
	{Name: "resolve", Fn: Resolve, Tools: []string{"dnsx"}},
	{Name: "ports", Fn: Ports, Tools: []string{"naabu"}},
	{Name: "http", Fn: HTTP, Tools: []string{"httpx"}},
	{Name: "content", Fn: Content, Tools: nil},
	{Name: "scan", Fn: Scan, Tools: []string{"nuclei"}},
}

// ConcurrentStages returns the stages that run as a pair.
//
// A stage in a concurrent pair has no ordering guarantee relative to its peer,
// so it must not read the peer's output.
func ConcurrentStages(name string) bool {
	switch name {
	case "ports", "http", "content", "scan":
		return true
	}
	return false
}

// Run executes the enabled stages in order and reports whether the run is clean.
//
// The order is:
//
//	domain mode  roots -> subs -> resolve -> {ports || http} -> {content || scan}
//	IP/ASN mode  targets -> ports -> http -> {content || scan}
//
// The braces are real concurrency, and the two modes differ on purpose. In domain
// mode ports and HTTP are independent once resolve has finished, so they run
// together. In IP mode HTTP consumes the host:port pairs the port stage produced,
// so running them together would be a race; they are serialised there.
//
// A failure is recorded per stage and does not abort the run, because a partial
// result is still useful and stages.json is where the gaps are visible. The
// returned error is non-zero when any stage failed.
func Run(ctx context.Context, e *Env, enabled func(string) bool) error {
	for _, group := range pipelineGroups(e.Opts.IPMode) {
		if ctx.Err() != nil {
			logging.Warn("interrupted before stage %s", group[0].name)
			break
		}

		var handles []*run.StageHandle
		for _, s := range group {
			// The targets stage is not a pipeline stage. It prepares the input
			// for an address or ASN run and decides for itself whether it
			// applies, so it is always considered enabled.
			on := enabled(s.name) || s.name == "targets"

			if !on {
				e.Run.Skip(s.name, "not selected")
				continue
			}

			if missing := e.Tools.Missing(s.tools...); len(missing) > 0 {
				// Skipped rather than failed. Every tool this stage needs is
				// absent, so there was nothing to do and nothing went wrong. The
				// run still produces everything the installed tools can find.
				e.Run.Skip(s.name, strings.Join(missing, ", ")+" not installed; "+
					"install with: "+tools.InstallHint())
				continue
			}

			// A single-stage group runs inline so its error is attributed to it
			// before the next stage starts. A multi-stage group is started in the
			// background and joined below.
			if len(group) == 1 {
				if err := e.Run.Stage(s.name, func() error { return s.fn(ctx, e) }); err != nil {
					logging.Debug("stage %s reported: %v", s.name, err)
				}
				continue
			}

			h, err := e.Run.StageAsync(s.name, func() error { return s.fn(ctx, e) })
			if err != nil {
				return err
			}
			handles = append(handles, h)
		}

		// Joining is what records the concurrent stages. The record has to be
		// made here, in the parent, because a goroutine cannot safely append to
		// the shared stage list from inside itself.
		for _, h := range handles {
			if err := h.Wait(); err != nil {
				logging.Debug("stage reported: %v", err)
			}
		}
	}

	return e.Run.Finalise()
}

// stageEntry is one stage with the tools it uses.
type stageEntry struct {
	name  string
	fn    func(context.Context, *Env) error
	tools []string
}

// pipelineGroups returns the stages in groups, where a group runs concurrently.
//
// The mode split is the important part. See Run.
func pipelineGroups(ipMode bool) [][]stageEntry {
	byName := make(map[string]stageEntry, len(Stages))
	for _, s := range Stages {
		byName[s.Name] = stageEntry{name: s.Name, fn: s.Fn, tools: s.Tools}
	}
	get := func(names ...string) []stageEntry {
		out := make([]stageEntry, 0, len(names))
		for _, n := range names {
			out = append(out, byName[n])
		}
		return out
	}

	if ipMode {
		// targets -> ports -> http, then content and scan together.
		return [][]stageEntry{
			get("targets"),
			get("roots", "subs", "resolve"),
			get("ports"),
			get("http"),
			get("content", "scan"),
		}
	}

	return [][]stageEntry{
		get("targets"),
		get("roots"),
		get("subs"),
		get("resolve"),
		get("ports", "http"),
		get("content", "scan"),
	}
}
