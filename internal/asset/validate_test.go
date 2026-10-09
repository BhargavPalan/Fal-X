package asset

import (
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/report"
)

// TestValidateModelNamesTheBadField pins that a run bundle with a value the schema
// would reject (a mode or stage status outside its CHECK constraint) fails with a
// message that says which field and what was expected, before any database work,
// instead of a raw "violates check constraint" error from deep inside the import.
func TestValidateModelNamesTheBadField(t *testing.T) {
	ok := func() *report.Model {
		return &report.Model{
			RunID: "r", Target: "t", Mode: "domain",
			Stages: []report.Stage{{Name: "subs", Status: "succeeded"}},
		}
	}

	if err := validateModel(ok()); err != nil {
		t.Fatalf("a valid run was rejected: %v", err)
	}
	m := ok()
	m.Mode = ""
	if err := validateModel(m); err != nil {
		t.Errorf("an empty mode is a run from before modes were recorded and must be accepted: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*report.Model)
		want   []string
	}{
		{"bad mode", func(m *report.Model) { m.Mode = "domain-scan" }, []string{"mode", "domain-scan", "domain, ip or asn"}},
		{"bad stage status", func(m *report.Model) { m.Stages[0].Status = "weird" }, []string{"subs", "status", "weird"}},
		{"missing run id", func(m *report.Model) { m.RunID = "" }, []string{"run id"}},
		{"missing target", func(m *report.Model) { m.Target = " " }, []string{"target"}},
		{"empty stage name", func(m *report.Model) { m.Stages[0].Name = "" }, []string{"stage", "name"}},
	}
	for _, tc := range cases {
		m := ok()
		tc.mutate(m)
		err := validateModel(m)
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: error %q does not mention %q", tc.name, err, w)
			}
		}
		if strings.Contains(err.Error(), "violates") || strings.Contains(err.Error(), "SQLSTATE") {
			t.Errorf("%s: a database error leaked through: %v", tc.name, err)
		}
	}
}
