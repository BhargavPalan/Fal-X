package prioritize

import "testing"

func TestExposurePoints(t *testing.T) {
	cases := map[string]int{
		"subdomain-takeover-confirmed":  25,
		"leaked-secret":                 25,
		"open-cloud-bucket":             20,
		"origin-ip-exposed":             15,
		"graphql-introspection-enabled": 8,
		"email-spoofable-no-spf-dmarc":  5,
		"CVE-2021-1234":                 0, // a CVE template carries no exposure class
		"":                              0,
	}
	for template, want := range cases {
		if got, _ := exposurePoints(template); got != want {
			t.Errorf("exposurePoints(%q) = %d, want %d", template, got, want)
		}
	}
}

func TestScoreCountsExposureAndReasonsSum(t *testing.T) {
	// A "medium" takeover finding: severity gives 20, exposure class adds 25.
	r := Score(Input{Severity: "medium", Exposure: "subdomain-takeover-confirmed"})
	sum := 0
	hasExposure := false
	for _, w := range r.Why {
		sum += w.Points
		if w.Signal == "exposure" && w.Points == 25 {
			hasExposure = true
		}
	}
	if !hasExposure {
		t.Errorf("expected a 25-point exposure reason, got %+v", r.Why)
	}
	if sum != r.Score {
		t.Errorf("reasons sum to %d but score is %d", sum, r.Score)
	}
	if r.Score < 45 {
		t.Errorf("a takeover should score meaningfully, got %d", r.Score)
	}
}
