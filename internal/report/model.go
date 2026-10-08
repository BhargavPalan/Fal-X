// Package report renders a finished run directory into a document someone else
// can read: Markdown for people, JSON for machines, SARIF for code-scanning
// tools.
//
// It is pure. It reads files the run already wrote and produces bytes; it makes
// no network request, touches no database, and launches nothing. That is what
// lets a report be produced on a different machine, long after the run.
//
// The distinction the whole project preserves is kept here: an artifact that is
// present but empty means its stage ran and found nothing, an artifact that is
// absent means the stage never got that far. Every collection in the Model
// carries a Present flag so a renderer can say "0 findings" and "the scan did
// not run" as two different things.
package report

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/run"
)

// SchemaVersion is the version of the JSON report format.
const SchemaVersion = 1

// Artifact is one stage output, with whether the stage produced it at all.
type Artifact[T any] struct {
	// Present is false when the file does not exist: the stage never got that
	// far. It is true for an empty file, which means the stage ran and found
	// nothing.
	Present bool `json:"present"`
	Items   []T  `json:"items"`
}

// Service is one live HTTP service, from the http stage.
type Service struct {
	URL    string   `json:"url"`
	Status int      `json:"status"`
	Title  string   `json:"title,omitempty"`
	Server string   `json:"server,omitempty"`
	Tech   []string `json:"tech,omitempty"`
	Host   string   `json:"host,omitempty"`
	Port   string   `json:"port,omitempty"`
}

// Finding is one template-scan result.
type Finding struct {
	Template string `json:"template"`
	Matcher  string `json:"matcher,omitempty"`
	Protocol string `json:"protocol"`
	Severity string `json:"severity"`
	Target   string `json:"target"`
	// Detail is whatever followed the target: extracted values and metadata.
	Detail string `json:"detail,omitempty"`
	// Raw is the original line, kept so nothing is lost to parsing.
	Raw string `json:"raw"`
}

// Stage is one pipeline stage as the run recorded it.
type Stage struct {
	Name            string `json:"name"`
	Status          string `json:"status"`
	ExitCode        int    `json:"exit_code"`
	DurationSeconds int64  `json:"duration_seconds"`
	Inputs          int    `json:"inputs"`
	Outputs         int    `json:"outputs"`
	Note            string `json:"note,omitempty"`
}

// Model is everything a renderer needs.
type Model struct {
	SchemaVersion int `json:"schema_version"`

	RunID          string            `json:"run_id"`
	Target         string            `json:"target"`
	Profile        string            `json:"profile,omitempty"`
	StartedAt      string            `json:"started_at"`
	ElapsedSeconds int64             `json:"elapsed_seconds"`
	DryRun         bool              `json:"dry_run"`
	ScopeAllowlist string            `json:"scope_allowlist,omitempty"`
	ScopeDenylist  string            `json:"scope_denylist,omitempty"`
	ScopeDigest    string            `json:"scope_fingerprint,omitempty"`
	ToolVersions   map[string]string `json:"tool_versions,omitempty"`

	Stages []Stage `json:"stages"`

	Subdomains Artifact[string]  `json:"subdomains"`
	Resolved   Artifact[string]  `json:"resolved"`
	OpenPorts  Artifact[string]  `json:"open_ports"`
	Services   Artifact[Service] `json:"services"`
	URLs       Artifact[string]  `json:"urls"`
	Endpoints  Artifact[string]  `json:"endpoints"`
	Findings   Artifact[Finding] `json:"findings"`
}

// The artifact locations inside a run directory. They mirror the methods on
// stage.Paths; this package does not import internal/stage because that would
// drag the whole pipeline into a renderer. internal/report's tests build a run
// from these same names, so a rename in stage.Paths that is not mirrored here
// shows up as an empty report rather than going unnoticed.
var (
	fileSubdomains = filepath.Join("2-subs", "subdomains.txt")
	fileResolved   = filepath.Join("3-resolve", "resolved.txt")
	fileOpenPorts  = filepath.Join("4-ports", "open.txt")
	fileProbe      = filepath.Join("5-http", "probe.json")
	fileURLs       = filepath.Join("6-content", "urls.txt")
	fileEndpoints  = filepath.Join("6-content", "endpoints.txt")
	fileFindings   = filepath.Join("7-scan", "findings.json")
)

// Load assembles the model for the run in dir.
func Load(dir string) (*Model, error) {
	man, stages, err := run.Load(dir)
	if err != nil {
		return nil, err
	}

	m := &Model{
		SchemaVersion:  SchemaVersion,
		RunID:          man.RunID,
		Target:         man.Target,
		Profile:        man.Profile,
		StartedAt:      man.StartedAt,
		ElapsedSeconds: man.Elapsed,
		DryRun:         man.DryRun,
		ScopeAllowlist: man.ScopeAllowlist,
		ScopeDenylist:  man.ScopeDenylist,
		ScopeDigest:    man.ScopeFinger,
		ToolVersions:   man.ToolVersions,
	}
	for _, s := range stages {
		m.Stages = append(m.Stages, Stage{
			Name: s.Name, Status: string(s.Status), ExitCode: s.ExitCode,
			DurationSeconds: s.DurationSeconds, Inputs: s.Inputs,
			Outputs: s.Outputs, Note: s.Note,
		})
	}

	if m.Subdomains, err = lines(dir, fileSubdomains); err != nil {
		return nil, err
	}
	if m.Resolved, err = lines(dir, fileResolved); err != nil {
		return nil, err
	}
	if m.OpenPorts, err = lines(dir, fileOpenPorts); err != nil {
		return nil, err
	}
	if m.URLs, err = lines(dir, fileURLs); err != nil {
		return nil, err
	}
	if m.Endpoints, err = lines(dir, fileEndpoints); err != nil {
		return nil, err
	}
	if m.Services, err = services(dir); err != nil {
		return nil, err
	}
	if m.Findings, err = findings(dir); err != nil {
		return nil, err
	}
	return m, nil
}

// readLines reads a text artifact. A missing file is reported as absent, not as
// an error, because "the stage never ran" is a normal state for a report.
func readLines(dir, rel string) (items []string, present bool, err error) {
	f, err := os.Open(filepath.Join(dir, rel)) //nolint:gosec // a path inside the chosen run directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("report: open %s: %w", rel, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			items = append(items, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, false, fmt.Errorf("report: read %s: %w", rel, err)
	}
	return items, true, nil
}

func lines(dir, rel string) (Artifact[string], error) {
	items, present, err := readLines(dir, rel)
	return Artifact[string]{Present: present, Items: items}, err
}

// probeRecord is the subset of an httpx record the report reads. httpx emits far
// more; decoding all of it would mean this struct drifting with the tool.
type probeRecord struct {
	URL       string   `json:"url"`
	Status    int      `json:"status_code"`
	Title     string   `json:"title"`
	WebServer string   `json:"webserver"`
	Tech      []string `json:"tech"`
	Host      string   `json:"host"`
	Port      string   `json:"port"`
}

// services parses probe.json, which is JSONL: one httpx record per line.
func services(dir string) (Artifact[Service], error) {
	raw, present, err := readLines(dir, fileProbe)
	if err != nil {
		return Artifact[Service]{}, err
	}
	a := Artifact[Service]{Present: present}
	for _, line := range raw {
		if !strings.HasPrefix(line, "{") {
			continue // httpx sometimes writes progress text; it is not a record
		}
		var r probeRecord
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		a.Items = append(a.Items, Service{
			URL: r.URL, Status: r.Status, Title: r.Title, Server: r.WebServer,
			Tech: r.Tech, Host: r.Host, Port: r.Port,
		})
	}
	return a, nil
}

// findingLine matches nuclei's default text output:
//
//	[template-id(:matcher)] [protocol] [severity] target ["extracted"] [meta]
var findingLine = regexp.MustCompile(`^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)(.*)$`)

// findings parses findings.json, which despite its name is nuclei's text output,
// one finding per line. A line that does not match is kept with severity
// "unknown" rather than dropped: losing a finding to a parsing gap is worse than
// showing it badly.
func findings(dir string) (Artifact[Finding], error) {
	raw, present, err := readLines(dir, fileFindings)
	if err != nil {
		return Artifact[Finding]{}, err
	}
	a := Artifact[Finding]{Present: present}
	for _, line := range raw {
		a.Items = append(a.Items, parseFinding(line))
	}
	sort.SliceStable(a.Items, func(i, j int) bool {
		return severityRank(a.Items[i].Severity) < severityRank(a.Items[j].Severity)
	})
	return a, nil
}

func parseFinding(line string) Finding {
	m := findingLine.FindStringSubmatch(line)
	if m == nil {
		return Finding{Severity: "unknown", Raw: line}
	}
	f := Finding{
		Template: m[1], Protocol: m[2], Severity: strings.ToLower(m[3]),
		Target: m[4], Detail: strings.TrimSpace(m[5]), Raw: line,
	}
	if i := strings.Index(f.Template, ":"); i > 0 {
		f.Template, f.Matcher = f.Template[:i], f.Template[i+1:]
	}
	return f
}

// severities in descending order of seriousness. Anything else ranks last.
var severities = []string{"critical", "high", "medium", "low", "info", "unknown"}

func severityRank(s string) int {
	for i, v := range severities {
		if v == s {
			return i
		}
	}
	return len(severities)
}

// StageByName returns the recorded stage, if the run has it.
func (m *Model) StageByName(name string) (Stage, bool) {
	for _, s := range m.Stages {
		if s.Name == name {
			return s, true
		}
	}
	return Stage{}, false
}

// Latest returns the newest run directory under root, optionally limited to one
// target. Run directories are named by a sortable timestamp, so the newest is the
// greatest name. A directory without a run.json is not a run and is ignored.
func Latest(root, target string) (string, error) {
	targets := []string{target}
	if target == "" {
		entries, err := os.ReadDir(root)
		if err != nil {
			return "", fmt.Errorf("report: read %s: %w", root, err)
		}
		targets = nil
		for _, e := range entries {
			if e.IsDir() {
				targets = append(targets, e.Name())
			}
		}
	}

	var best, bestStamp string
	for _, t := range targets {
		entries, err := os.ReadDir(filepath.Join(root, t))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if _, err := os.Stat(filepath.Join(root, t, e.Name(), "run.json")); err != nil {
				continue
			}
			if e.Name() > bestStamp {
				bestStamp, best = e.Name(), filepath.Join(root, t, e.Name())
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("report: no run found under %s", root)
	}
	return best, nil
}
