package prioritize

import (
	"strings"
	"testing"
	"time"
)

func sampleRanked() []Ranked {
	mk := func(asset, tmpl, sev, cve string, in Input) Ranked {
		in.Severity, in.CVE = sev, cve
		return Ranked{
			Asset: asset, Kind: "service",
			Finding: Finding{Severity: sev, Template: tmpl, CVE: cve},
			Input:   in, Result: Score(in),
		}
	}
	return []Ranked{
		mk("a.example.test:443", "CVE-2021-44228", "low", "CVE-2021-44228", Input{KEV: true, Ransomware: true}),
		mk("b.example.test:22", "CVE-2023-48795", "medium", "CVE-2023-48795", Input{EPSS: f32(0.9355), EPSSPercentile: f32(0.998)}),
		mk("c.example.test:22", "ssh-weak-mac-algo", "low", "", Input{}),
	}
}

var when = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func TestRenderMarkdownSummarisesAndExplains(t *testing.T) {
	md := string(RenderMarkdown(sampleRanked(), 3, when))

	for _, want := range []string{
		"# Fal-X prioritised findings",
		"2026-10-09",
		"**1** Act",
		"**1** Attend",
		"**1** Track",
		"CVE-2021-44228",
		"CISA's Known Exploited Vulnerabilities list",
		"99.8% percentile",
		"internet exposure is not assessed",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report is missing %q:\n%s", want, md)
		}
	}
	// Most urgent first.
	if strings.Index(md, "a.example.test") > strings.Index(md, "c.example.test") {
		t.Error("findings are not in rank order")
	}
	// Every derivation is present, so a reader can audit any score.
	if got := strings.Count(md, "scanner severity"); got != 3 {
		t.Errorf("derivations for %d of 3 findings", got)
	}
}

func TestRenderMarkdownSaysWhenItIsPartial(t *testing.T) {
	md := string(RenderMarkdown(sampleRanked()[:2], 3, when))
	if !strings.Contains(md, "2 of 3") {
		t.Errorf("a truncated list must say so:\n%s", md)
	}
}

func TestRenderMarkdownTreatsScannedTextAsData(t *testing.T) {
	r := sampleRanked()[:1]
	r[0].Asset = "[click](http://evil.example)|<b>x</b>"
	r[0].Finding.Template = "`rm -rf`"
	md := string(RenderMarkdown(r, 1, when))
	for _, bad := range []string{"[click](http://evil.example)", "<b>", "`rm -rf`"} {
		if strings.Contains(md, bad) {
			t.Errorf("hostile text survived as markup: %q in\n%s", bad, md)
		}
	}
}

func TestRenderMarkdownWithNothingToRank(t *testing.T) {
	md := string(RenderMarkdown(nil, 0, when))
	if !strings.Contains(md, "No findings") {
		t.Errorf("empty report should say there is nothing to rank:\n%s", md)
	}
}
