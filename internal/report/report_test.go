package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/run"
)

// writeFile writes a stage artifact inside a run directory.
func writeFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// newRun builds a real run directory through the run package, so Load is tested
// against exactly what the pipeline writes. Only synthetic data is used.
func newRun(t *testing.T) string {
	t.Helper()
	r, err := run.Init(t.TempDir(), "example.com", "20261003-123456")
	if err != nil {
		t.Fatal(err)
	}
	r.SetTarget("example.com")
	r.SetProfile("normal")
	r.SetToolVersion("httpx", "v1.12.0")
	_ = r.Stage("subs", func() error { return nil })
	r.SetNote("ports", "naabu missing")
	_ = r.Stage("ports", func() error { return run.ErrSkip })
	_ = r.Stage("scan", func() error { return nil })
	if err := r.Finalise(); err != nil {
		t.Fatal(err)
	}
	return r.Dir
}

const probeLine = `{"url":"http://example.com","status_code":200,"title":"Example | <b>Domain</b>","webserver":"nginx","tech":["Nginx"],"host":"example.com","port":"80"}`

func TestLoadParsesArtifacts(t *testing.T) {
	dir := newRun(t)
	writeFile(t, dir, fileSubdomains, "www.example.com\napi.example.com\n")
	writeFile(t, dir, fileProbe, "[INF] progress text\n"+probeLine+"\n")
	writeFile(t, dir, fileFindings, strings.Join([]string{
		`[ssh-weak-mac-algo] [javascript] [low] 192.0.2.10:22`,
		`[CVE-2023-48795] [javascript] [medium] 192.0.2.10:22 ["Vulnerable to Terrapin"]`,
		`[apache-mod-negotiation-listing:exposed_files] [http] [low] http://example.com/index ["index.html"] [path="/index"]`,
		`something nuclei printed that is not a finding`,
	}, "\n")+"\n")

	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Target != "example.com" || m.ToolVersions["httpx"] != "v1.12.0" {
		t.Errorf("manifest not carried over: %+v", m)
	}
	if got := len(m.Subdomains.Items); got != 2 {
		t.Errorf("subdomains = %d, want 2", got)
	}
	if len(m.Services.Items) != 1 || m.Services.Items[0].Status != 200 {
		t.Fatalf("services = %+v, want the one probe record and no progress line", m.Services.Items)
	}

	f := m.Findings.Items
	if len(f) != 4 {
		t.Fatalf("findings = %d, want 4 (the unparsed line is kept)", len(f))
	}
	// Sorted by severity: medium first, unknown last.
	if f[0].Severity != "medium" || f[0].Template != "CVE-2023-48795" {
		t.Errorf("first finding = %+v, want the medium CVE", f[0])
	}
	if f[len(f)-1].Severity != "unknown" || f[len(f)-1].Raw == "" {
		t.Errorf("unparsed line not kept last: %+v", f[len(f)-1])
	}
	var matcher Finding
	for _, x := range f {
		if x.Template == "apache-mod-negotiation-listing" {
			matcher = x
		}
	}
	if matcher.Matcher != "exposed_files" {
		t.Errorf("matcher not split from template: %+v", matcher)
	}
}

// TestEmptyIsNotMissing pins the project's central distinction in the report.
func TestEmptyIsNotMissing(t *testing.T) {
	dir := newRun(t)
	writeFile(t, dir, fileFindings, "") // the scan ran and found nothing
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Findings.Present || len(m.Findings.Items) != 0 {
		t.Fatalf("empty file: %+v, want present and empty", m.Findings)
	}
	if m.Services.Present {
		t.Fatal("absent probe.json reported as present")
	}

	md := string(RenderMarkdown(m))
	if !strings.Contains(md, "The scan ran and reported no findings") {
		t.Errorf("empty findings not reported as a clean scan:\n%s", md)
	}
	if !strings.Contains(md, "Not produced") || !strings.Contains(md, "the http stage is not in this run") {
		t.Errorf("missing probe.json not reported as not produced:\n%s", md)
	}
}

func TestMissingArtifactExplainsTheStage(t *testing.T) {
	dir := newRun(t) // ports was skipped with a note
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	md := string(RenderMarkdown(m))
	if !strings.Contains(md, "the ports stage skipped: naabu missing") {
		t.Errorf("skipped stage and its note not shown:\n%s", md)
	}
}

func TestMarkdownTreatsScannedTextAsData(t *testing.T) {
	dir := newRun(t)
	writeFile(t, dir, fileProbe, probeLine+"\n")
	m, _ := Load(dir)
	md := string(RenderMarkdown(m))
	if strings.Contains(md, "<b>") {
		t.Errorf("markup from a page title survived:\n%s", md)
	}
	if !strings.Contains(md, `Example \| &lt;b&gt;Domain&lt;/b&gt;`) {
		t.Errorf("title not escaped for a table cell:\n%s", md)
	}
}

func TestRenderJSONRoundTrips(t *testing.T) {
	dir := newRun(t)
	writeFile(t, dir, fileFindings, "[x] [http] [high] http://example.com\n")
	m, _ := Load(dir)
	b, err := RenderJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	var back Model
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("report JSON does not parse: %v", err)
	}
	if back.SchemaVersion != SchemaVersion || len(back.Findings.Items) != 1 {
		t.Errorf("round trip lost data: %+v", back)
	}
}

func TestSARIFMapsSeverityAndRules(t *testing.T) {
	dir := newRun(t)
	writeFile(t, dir, fileFindings, strings.Join([]string{
		`[tmpl-a] [http] [critical] http://example.com/a`,
		`[tmpl-a] [http] [critical] http://example.com/b`,
		`[tmpl-b] [dns] [low] example.com`,
		`[tmpl-c] [http] [medium] http://example.com/c`,
	}, "\n")+"\n")
	m, _ := Load(dir)
	b, err := RenderSARIF(m)
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatalf("SARIF does not parse: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("bad SARIF envelope: %+v", log)
	}
	r := log.Runs[0]
	if len(r.Results) != 4 {
		t.Errorf("results = %d, want 4", len(r.Results))
	}
	if len(r.Tool.Driver.Rules) != 3 {
		t.Errorf("rules = %d, want 3 distinct templates", len(r.Tool.Driver.Rules))
	}
	level := map[string]string{}
	for _, x := range r.Results {
		level[x.RuleID] = x.Level
	}
	if level["tmpl-a"] != "error" || level["tmpl-b"] != "note" || level["tmpl-c"] != "warning" {
		t.Errorf("severity mapping wrong: %v", level)
	}
}

func TestSARIFWithNoFindingsStillHasResults(t *testing.T) {
	dir := newRun(t)
	m, _ := Load(dir)
	b, _ := RenderSARIF(m)
	if !strings.Contains(string(b), `"results": []`) {
		t.Errorf("empty SARIF run must carry an empty results array:\n%s", b)
	}
}

func TestLatestPicksNewestRun(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"a.test/20261001-000000", "a.test/20261003-000000", "b.test/20261002-000000"} {
		writeFile(t, root, filepath.Join(p, "run.json"), "{}")
	}
	writeFile(t, root, filepath.Join("a.test", "20261009-000000", "notes.txt"), "no run.json here")

	got, err := Latest(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "20261003-000000" {
		t.Errorf("Latest = %s, want the newest directory that has a run.json", got)
	}
	got, _ = Latest(root, "b.test")
	if filepath.Base(got) != "20261002-000000" {
		t.Errorf("Latest for b.test = %s", got)
	}
	if _, err := Latest(t.TempDir(), ""); err == nil {
		t.Error("Latest on an empty root returned no error")
	}
}

func TestLoadRefusesUnknownSchema(t *testing.T) {
	dir := newRun(t)
	b, _ := os.ReadFile(filepath.Join(dir, "stages.json"))
	bad := strings.Replace(string(b), `"schema_version": 1`, `"schema_version": 99`, 1)
	writeFile(t, dir, "stages.json", bad)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "schema version") {
		t.Errorf("Load accepted an unknown schema version: %v", err)
	}
}

func TestParseFormat(t *testing.T) {
	for _, ok := range []string{"md", "JSON", " sarif "} {
		if _, err := ParseFormat(ok); err != nil {
			t.Errorf("ParseFormat(%q): %v", ok, err)
		}
	}
	if _, err := ParseFormat("pdf"); err == nil {
		t.Error("ParseFormat accepted pdf")
	}
}
