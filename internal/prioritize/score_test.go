package prioritize

import (
	"strings"
	"testing"
)

func f32(v float32) *float32 { return &v }

func reasonPoints(r Result) map[string]int {
	m := map[string]int{}
	for _, x := range r.Why {
		m[x.Signal] = x.Points
	}
	return m
}

func TestScoreEveryPointIsAttributed(t *testing.T) {
	r := Score(Input{
		Severity: "medium", CVE: "CVE-2023-48795", EPSS: f32(0.9355), EPSSPercentile: f32(0.998),
		Criticality: 80,
	})
	sum := 0
	for _, x := range r.Why {
		if x.Signal == "" || x.Detail == "" {
			t.Errorf("reason without a name or explanation: %+v", x)
		}
		sum += x.Points
	}
	if sum != r.Score {
		t.Errorf("score %d but the reasons add up to %d: a point is unattributed", r.Score, sum)
	}
	got := reasonPoints(r)
	if got["scanner severity"] != 20 {
		t.Errorf("medium severity = %d points, want 20", got["scanner severity"])
	}
	if got["EPSS"] != 28 { // round(0.9355 * 30)
		t.Errorf("EPSS 0.9355 = %d points, want 28", got["EPSS"])
	}
	if got["asset criticality"] != 8 { // round(80 / 100 * 10)
		t.Errorf("criticality 80 = %d points, want 8", got["asset criticality"])
	}
	// The absence of KEV is stated, but earns nothing.
	if p, ok := got["CISA KEV"]; !ok || p != 0 {
		t.Errorf("a CVE that is not in KEV must be stated with 0 points, got present=%v points=%d", ok, p)
	}
}

func TestCVSSAddsAttributedPoints(t *testing.T) {
	score := f32(5.9)
	r := Score(Input{Severity: "medium", CVE: "CVE-2023-48795", CVSS: score, CVSSVersion: "3.1"})
	got := reasonPoints(r)
	if got["CVSS"] != 9 { // round(5.9 / 10 * 15)
		t.Errorf("CVSS 5.9 = %d points, want 9", got["CVSS"])
	}
	var detail string
	for _, x := range r.Why {
		if x.Signal == "CVSS" {
			detail = x.Detail
		}
	}
	if !strings.Contains(detail, "3.1") || !strings.Contains(detail, "5.9") {
		t.Errorf("the CVSS reason must name the score and its version: %q", detail)
	}

	// No score fetched is stated, with the way to fix it.
	r = Score(Input{Severity: "medium", CVE: "CVE-2023-48795"})
	for _, x := range r.Why {
		if x.Signal == "CVSS" && (x.Points != 0 || !strings.Contains(x.Detail, "intel enrich")) {
			t.Errorf("a missing CVSS score must say how to fetch it: %+v", x)
		}
	}
	// A finding that names no CVE has no CVSS line at all.
	for _, x := range Score(Input{Severity: "low"}).Why {
		if x.Signal == "CVSS" {
			t.Errorf("a finding with no CVE got a CVSS line: %+v", x)
		}
	}
}

func TestDecision(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		want string
	}{
		{"known exploited always acts", Input{Severity: "low", CVE: "CVE-2021-44228", KEV: true}, Act},
		{"high EPSS attends", Input{Severity: "low", CVE: "CVE-2023-48795", EPSS: f32(0.9)}, Attend},
		{"high score attends", Input{Severity: "critical", Criticality: 100}, Attend},
		{"a plain low finding is tracked", Input{Severity: "low"}, Track},
		{"low EPSS stays tracked", Input{Severity: "low", CVE: "CVE-2020-1", EPSS: f32(0.01)}, Track},
	}
	for _, tc := range cases {
		if got := Score(tc.in).Decision; got != tc.want {
			t.Errorf("%s: decision = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestKEVAndRansomwareRaiseTheScore(t *testing.T) {
	base := Score(Input{Severity: "high", CVE: "CVE-2021-44228"})
	kev := Score(Input{Severity: "high", CVE: "CVE-2021-44228", KEV: true})
	ransom := Score(Input{Severity: "high", CVE: "CVE-2021-44228", KEV: true, Ransomware: true})
	if base.Score >= kev.Score || kev.Score >= ransom.Score {
		t.Errorf("scores %d < %d < %d expected: KEV and ransomware use must each add", base.Score, kev.Score, ransom.Score)
	}
}

func TestScoreIsCappedAndNeverNegative(t *testing.T) {
	r := Score(Input{Severity: "critical", CVE: "CVE-1-1", KEV: true, Ransomware: true,
		EPSS: f32(1), Criticality: 100})
	if r.Score != 100 {
		t.Errorf("score = %d, want the 100 cap", r.Score)
	}
	// Capping must be visible, not silent: the signals before the cap exceed 100,
	// and a negative "cap" reason brings the total back so the derivation adds up.
	before := 0
	var capPoints int
	for _, x := range r.Why {
		if x.Signal == "cap" {
			capPoints = x.Points
			continue
		}
		before += x.Points
	}
	if before <= 100 {
		t.Fatalf("test input should exceed the cap, signals sum to %d", before)
	}
	if capPoints != 100-before {
		t.Errorf("cap reason = %d, want %d so the reasons sum to the score", capPoints, 100-before)
	}
	if Score(Input{}).Score < 0 {
		t.Error("negative score")
	}
}

func TestMissingSignalsAreSaidNotInvented(t *testing.T) {
	r := Score(Input{Severity: "medium", CVE: "CVE-2020-9999"}) // a CVE with no EPSS and not in KEV
	var notes []string
	for _, x := range r.Why {
		if x.Points == 0 {
			notes = append(notes, x.Signal+": "+x.Detail)
		}
	}
	joined := strings.Join(notes, "|")
	if !strings.Contains(joined, "EPSS") {
		t.Errorf("a missing EPSS score must be stated, not silently skipped: %q", joined)
	}
	if !strings.Contains(joined, "exposure") {
		t.Errorf("exposure is not assessed and must say so: %q", joined)
	}
}

func TestParseFinding(t *testing.T) {
	cases := []struct {
		in             string
		sev, tmpl, cve string
	}{
		{`medium CVE-2023-48795 ["Vulnerable to Terrapin"]`, "medium", "CVE-2023-48795", "CVE-2023-48795"},
		{`low ssh-weak-mac-algo`, "low", "ssh-weak-mac-algo", ""},
		{`low apache-mod-negotiation-listing:exposed_files ["index.html"]`, "low", "apache-mod-negotiation-listing:exposed_files", ""},
		{`unknown some raw nuclei line`, "unknown", "some", ""},
		{``, "unknown", "", ""},
	}
	for _, tc := range cases {
		f := ParseFinding(tc.in)
		if f.Severity != tc.sev || f.Template != tc.tmpl || f.CVE != tc.cve {
			t.Errorf("ParseFinding(%q) = %+v, want severity %q template %q cve %q", tc.in, f, tc.sev, tc.tmpl, tc.cve)
		}
	}
}

func TestMatchedKEVActsOnlyWhenTheVersionIsMatched(t *testing.T) {
	kev := func(tier, conf string) Result {
		return Score(Input{Severity: "high", CVE: "CVE-2021-41773", KEV: true, Match: tier, MatchConfidence: conf})
	}
	if got := kev("affected", "high").Decision; got != Act {
		t.Errorf("a known-exploited CVE on a matched version = %s, want Act", got)
	}
	// Conditional, possible and unverified all leave applicability unconfirmed: the
	// product is present but NVD has not tied this version to the CVE, or has tied it
	// only together with something the matcher did not check. Known-exploited is then a
	// reason to Attend, not yet to Act.
	for _, tier := range []string{"conditional", "possible", "unverified"} {
		if got := kev(tier, "low").Decision; got != Attend {
			t.Errorf("%s: a known-exploited CVE on an unconfirmed version = %s, want Attend, because the product being present is not the version being confirmed affected", tier, got)
		}
	}
	if got := Score(Input{Severity: "high", CVE: "CVE-2021-41773", KEV: true}).Decision; got != Act {
		t.Errorf("a scanner finding on a known-exploited CVE = %s, want Act", got)
	}
}

func TestMatchConfidenceLowersTheScoreAndIsShown(t *testing.T) {
	score := func(tier, conf string) Result {
		return Score(Input{Severity: "high", CVE: "CVE-2020-0001", Match: tier, MatchConfidence: conf})
	}
	confirmed, backported, guessed := score("affected", "high"), score("affected", "medium"), score("unverified", "low")
	if confirmed.Score <= backported.Score || backported.Score <= guessed.Score {
		t.Errorf("scores %d, %d, %d should fall as confidence falls", confirmed.Score, backported.Score, guessed.Score)
	}
	shown := false
	for _, w := range guessed.Why {
		if w.Signal == "match confidence" && w.Points < 0 {
			shown = true
		}
	}
	if !shown {
		t.Errorf("the penalty is not in the derivation: %+v", guessed.Why)
	}
	if plain := Score(Input{Severity: "high", CVE: "CVE-2020-0001"}); plain.Score != confirmed.Score {
		t.Errorf("a high-confidence match should cost nothing: %d vs %d", confirmed.Score, plain.Score)
	}
}

func TestScoreNeverGoesNegativeAndStillAddsUp(t *testing.T) {
	r := Score(Input{Severity: "info", CVE: "CVE-2020-0001", Match: "unverified", MatchConfidence: "low"})
	if r.Score < 0 {
		t.Fatalf("score = %d", r.Score)
	}
	sum := 0
	for _, w := range r.Why {
		sum += w.Points
	}
	if sum != r.Score {
		t.Errorf("reasons sum to %d, score is %d: %+v", sum, r.Score, r.Why)
	}
}
