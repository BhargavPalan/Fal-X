package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStageNotesCannotInjectMarkup pins that the prose lines explaining a missing
// artifact escape the stage status and note. The tables did; these did not, so a
// crafted stages.json (an untrusted run bundle handed to `report --run`) rendered a
// live link and raw HTML in the report.
func TestStageNotesCannotInjectMarkup(t *testing.T) {
	dir := newRun(t)

	// Replace stages.json with one whose scan stage carries hostile text.
	hostile := `{
  "schema_version": 1,
  "run_id": "x",
  "stages": [
    {"name": "scan", "status": "succeeded [CLICK ME](http://evil.example/pwn)",
     "note": "<img src=x onerror=alert(1)> and ` + "`code`" + `"},
    {"name": "http", "status": "skipped", "note": "[b](http://evil.example)"},
    {"name": "ports", "status": "failed", "note": "<b>x</b>"},
    {"name": "subs", "status": "succeeded", "note": "![i](http://evil.example/x.png)"}
  ],
  "failed": 1, "total_duration_seconds": 1
}`
	if err := os.WriteFile(filepath.Join(dir, "stages.json"), []byte(hostile), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	md := string(RenderMarkdown(m))

	for _, live := range []string{
		"[CLICK ME](http://evil.example/pwn)",
		"[b](http://evil.example)",
		"![i](http://evil.example/x.png)",
		"<img", "<b>", "`code`",
	} {
		if strings.Contains(md, live) {
			t.Errorf("hostile text survived as live markup %q in:\n%s", live, md)
		}
	}
}

// TestEveryUntrustedFieldIsEscaped covers the remaining places the renderer prints
// text from the run bundle: the run id and scope fingerprint (from run.json) and a
// finding's severity and raw line (from findings.json). Two of those sat in code
// spans, where a backtick in the value ends the span and the rest renders live.
func TestEveryUntrustedFieldIsEscaped(t *testing.T) {
	dir := newRun(t)

	man := `{"run_id":"r` + "`" + `[RUNID](http://evil.example)","target":"t","scope_fingerprint":"f` + "`" + `<i>FP</i>",
 "stamp":"s","started_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, "run.json"), []byte(man), 0o600); err != nil {
		t.Fatal(err)
	}
	// A finding line that does not parse keeps its raw text and severity "unknown";
	// one that parses can carry markup in its severity position.
	writeFile(t, dir, fileFindings,
		"[x] [http] [high] http://example.com\n"+
			"[y] [http] [<u>SEV</u>] http://example.com\n"+
			"raw line with `tick` and [link](http://evil.example)\n")

	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	md := string(RenderMarkdown(m))
	for _, live := range []string{
		"[RUNID](http://evil.example)", "<i>", "<u>", "[link](http://evil.example)", "`tick`",
	} {
		if strings.Contains(md, live) {
			t.Errorf("untrusted text survived as live markup %q in:\n%s", live, md)
		}
	}
}
