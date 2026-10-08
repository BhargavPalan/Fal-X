package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Format names an output format.
type Format string

// The supported formats.
const (
	FormatMarkdown Format = "md"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif"
)

// Extension is the file extension for a format.
func (f Format) Extension() string {
	switch f {
	case FormatMarkdown:
		return "md"
	case FormatSARIF:
		return "sarif"
	default:
		return "json"
	}
}

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(strings.TrimSpace(s))); f {
	case FormatMarkdown, FormatJSON, FormatSARIF:
		return f, nil
	}
	return "", fmt.Errorf("unknown report format %q (expected md, json or sarif)", s)
}

// Render renders the model in the given format.
func Render(m *Model, f Format) ([]byte, error) {
	switch f {
	case FormatMarkdown:
		return RenderMarkdown(m), nil
	case FormatJSON:
		return RenderJSON(m)
	case FormatSARIF:
		return RenderSARIF(m)
	}
	return nil, fmt.Errorf("unknown report format %q", f)
}

// RenderJSON renders the model as indented JSON.
func RenderJSON(m *Model) ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// maxList caps a rendered list of hosts or ports, and maxURLs the much noisier
// crawled-URL lists. The JSON report always carries everything.
const (
	maxList = 50
	maxURLs = 15
)

// RenderMarkdown renders the model for people.
func RenderMarkdown(m *Model) []byte {
	var b bytes.Buffer
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("# Fal-X report: %s\n\n", cell(m.Target))
	w("| | |\n|---|---|\n")
	w("| Run | `%s` |\n", m.RunID)
	w("| Started | %s |\n", cell(m.StartedAt))
	w("| Profile | %s |\n", cell(orDash(m.Profile)))
	w("| Elapsed | %ds |\n", m.ElapsedSeconds)
	if m.DryRun {
		w("| Mode | **dry run: nothing was contacted** |\n")
	}
	if m.ScopeDigest != "" {
		w("| Scope fingerprint | `%s` |\n", m.ScopeDigest)
	}
	w("\n")

	writeSummary(&b, m)
	writeStages(&b, m)
	writeFindings(&b, m)
	writeServices(&b, m)
	writeList(&b, m, "Open ports", "ports", m.OpenPorts, maxList)
	writeList(&b, m, "Subdomains", "subs", m.Subdomains, maxList)
	writeList(&b, m, "Resolved hosts", "resolve", m.Resolved, maxList)
	writeList(&b, m, "URLs", "content", m.URLs, maxURLs)
	if m.Endpoints.Present && m.URLs.Present && slices.Equal(m.Endpoints.Items, m.URLs.Items) {
		w("## Endpoints\n\nIdentical to the URL list above.\n\n")
	} else {
		writeList(&b, m, "Endpoints", "content", m.Endpoints, maxURLs)
	}

	if len(m.ToolVersions) > 0 {
		w("## Tools\n\n")
		names := make([]string, 0, len(m.ToolVersions))
		for n := range m.ToolVersions {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			w("- %s %s\n", n, cell(m.ToolVersions[n]))
		}
		w("\n")
	}
	return b.Bytes()
}

func writeSummary(b *bytes.Buffer, m *Model) {
	fmt.Fprintf(b, "## Summary\n\n| | |\n|---|---|\n")
	row := func(label string, present bool, n int, stage string) {
		if present {
			fmt.Fprintf(b, "| %s | %d |\n", label, n)
			return
		}
		fmt.Fprintf(b, "| %s | not produced (%s) |\n", label, stageState(m, stage))
	}
	row("Findings", m.Findings.Present, len(m.Findings.Items), "scan")
	row("Live HTTP services", m.Services.Present, len(m.Services.Items), "http")
	row("Open ports", m.OpenPorts.Present, len(m.OpenPorts.Items), "ports")
	row("Subdomains", m.Subdomains.Present, len(m.Subdomains.Items), "subs")
	row("Resolved hosts", m.Resolved.Present, len(m.Resolved.Items), "resolve")
	row("URLs", m.URLs.Present, len(m.URLs.Items), "content")
	fmt.Fprintln(b)
}

func writeStages(b *bytes.Buffer, m *Model) {
	fmt.Fprintf(b, "## Stages\n\n| Stage | Status | Duration | Note |\n|---|---|---|---|\n")
	for _, s := range m.Stages {
		fmt.Fprintf(b, "| %s | %s | %ds | %s |\n", s.Name, s.Status, s.DurationSeconds, cell(s.Note))
	}
	fmt.Fprintln(b)
}

func writeFindings(b *bytes.Buffer, m *Model) {
	fmt.Fprintf(b, "## Findings\n\n")
	if !m.Findings.Present {
		fmt.Fprintf(b, "_Not produced: %s._\n\n", stageState(m, "scan"))
		return
	}
	if len(m.Findings.Items) == 0 {
		fmt.Fprintf(b, "The scan ran and reported no findings.\n\n")
		return
	}
	cur := ""
	for _, f := range m.Findings.Items {
		if f.Severity != cur {
			if cur != "" {
				fmt.Fprintln(b)
			}
			cur = f.Severity
			fmt.Fprintf(b, "### %s\n\n", strings.ToUpper(cur))
		}
		id := f.Template
		if f.Matcher != "" {
			id += ":" + f.Matcher
		}
		if id == "" {
			fmt.Fprintf(b, "- `%s`\n", f.Raw)
			continue
		}
		fmt.Fprintf(b, "- **%s** (%s) %s", cell(id), cell(f.Protocol), cell(f.Target))
		if f.Detail != "" {
			fmt.Fprintf(b, " %s", cell(f.Detail))
		}
		fmt.Fprintln(b)
	}
	fmt.Fprintln(b)
}

func writeServices(b *bytes.Buffer, m *Model) {
	fmt.Fprintf(b, "## Live HTTP services\n\n")
	if !m.Services.Present {
		fmt.Fprintf(b, "_Not produced: %s._\n\n", stageState(m, "http"))
		return
	}
	if len(m.Services.Items) == 0 {
		fmt.Fprintf(b, "The probe ran and found no live services.\n\n")
		return
	}
	fmt.Fprintf(b, "| URL | Status | Title | Server | Tech |\n|---|---|---|---|---|\n")
	for _, s := range m.Services.Items {
		fmt.Fprintf(b, "| %s | %d | %s | %s | %s |\n", cell(s.URL), s.Status,
			cell(s.Title), cell(s.Server), cell(strings.Join(s.Tech, ", ")))
	}
	fmt.Fprintln(b)
}

func writeList(b *bytes.Buffer, m *Model, title, stage string, a Artifact[string], limit int) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if !a.Present {
		fmt.Fprintf(b, "_Not produced: %s._\n\n", stageState(m, stage))
		return
	}
	if len(a.Items) == 0 {
		fmt.Fprintf(b, "The stage ran and found none.\n\n")
		return
	}
	for i, it := range a.Items {
		if i == limit {
			fmt.Fprintf(b, "- _… and %d more (see the JSON report)_\n", len(a.Items)-limit)
			break
		}
		fmt.Fprintf(b, "- %s\n", cell(it))
	}
	fmt.Fprintln(b)
}

// stageState explains in words why an artifact is missing, from what the run
// recorded about the stage that should have produced it.
func stageState(m *Model, stage string) string {
	s, ok := m.StageByName(stage)
	if !ok {
		return "the " + stage + " stage is not in this run"
	}
	out := "the " + stage + " stage " + s.Status
	if s.Note != "" {
		out += ": " + s.Note
	}
	return out
}

// cell makes untrusted text safe inside a Markdown table cell or list item. Page
// titles and banners come from the scanned host, so they are data, not markup.
func cell(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// SARIF 2.1.0, the subset a code-scanning consumer needs.
type (
	sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	sarifDriver struct {
		Name           string      `json:"name"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	sarifRule struct {
		ID               string    `json:"id"`
		ShortDescription sarifText `json:"shortDescription"`
	}
	sarifText struct {
		Text string `json:"text"`
	}
	sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifText       `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}
	sarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
)

// sarifLevel maps a nuclei severity onto a SARIF level.
func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// RenderSARIF renders the findings as SARIF 2.1.0.
//
// Only findings are SARIF results; the rest of a run is not a defect in anything.
// The results array is always present, even when empty, because some consumers
// reject a run without one.
func RenderSARIF(m *Model) ([]byte, error) {
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "fal-x",
				InformationURI: "https://github.com/BhargavPalan/Fal-X",
				Rules:          []sarifRule{},
			}},
			Results: []sarifResult{},
		}},
	}
	run := &log.Runs[0]

	seen := map[string]bool{}
	for _, f := range m.Findings.Items {
		id := f.Template
		if id == "" {
			id = "unparsed-finding"
		}
		if !seen[id] {
			seen[id] = true
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules,
				sarifRule{ID: id, ShortDescription: sarifText{Text: id}})
		}
		msg := id
		if f.Detail != "" {
			msg += " " + f.Detail
		}
		if f.Template == "" {
			msg = f.Raw
		}
		res := sarifResult{
			RuleID:  id,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: msg},
		}
		if f.Target != "" {
			var loc sarifLocation
			loc.PhysicalLocation.ArtifactLocation.URI = f.Target
			res.Locations = []sarifLocation{loc}
		}
		run.Results = append(run.Results, res)
	}

	b, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
