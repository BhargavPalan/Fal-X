package prioritize

import (
	"context"
	"database/sql"
	"sort"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/intel"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// Ranked is one finding with its asset, its score and its derivation.
type Ranked struct {
	Asset      string
	Kind       string
	Finding    Finding
	Input      Input
	Result     Result
	IntelKnown bool // the named CVE is in the synced intelligence at all
	// Source is "scanner" for a finding a tool reported and "match" for a CVE
	// inferred from the software the asset runs.
	Source string
}

// Rank scores every scanner finding the tenant has, most urgent first. Ties break
// by asset and template so the order is stable between runs.
//
// It reads the intelligence from the same transaction. The intelligence tables are
// global, so a tenant's transaction can read them without leaving its own scope.
func Rank(ctx context.Context, tx *sql.Tx) ([]Ranked, error) {
	return rank(ctx, tx, false)
}

// RankAll is Rank with the CVEs inferred from the software each asset runs
// (internal/match) ranked alongside the scanner findings.
func RankAll(ctx context.Context, tx *sql.Tx) ([]Ranked, error) {
	return rank(ctx, tx, true)
}

func rank(ctx context.Context, tx *sql.Tx, withMatches bool) ([]Ranked, error) {
	rows, err := store.ListFindings(ctx, tx)
	if err != nil {
		return nil, err
	}

	cache := map[string]*intel.Detail{}
	detail := func(cve string) (*intel.Detail, error) {
		if d, ok := cache[cve]; ok {
			return d, nil
		}
		d, err := intel.Show(ctx, tx, cve)
		if err != nil {
			return nil, err
		}
		cache[cve] = d
		return d, nil
	}
	// apply copies what the intelligence says about a CVE onto the scorer's input.
	apply := func(r *Ranked, in *Input) error {
		d, err := detail(r.Finding.CVE)
		if err != nil {
			return err
		}
		r.IntelKnown = d.Known
		if d.KEV != nil {
			in.KEV, in.Ransomware = true, d.KEV.KnownRansomware
		}
		if d.NVD != nil && d.NVD.CVSSScore != nil {
			in.CVSS, in.CVSSVersion = d.NVD.CVSSScore, d.NVD.CVSSVersion
		}
		if d.EPSS != nil {
			s, p := d.EPSS.Score, d.EPSS.Percentile
			in.EPSS, in.EPSSPercentile = &s, &p
		}
		return nil
	}

	out := make([]Ranked, 0, len(rows))
	for _, row := range rows {
		f := ParseFinding(row.Value)
		in := Input{Severity: f.Severity, CVE: f.CVE, Criticality: row.Criticality, Exposure: f.Template}
		r := Ranked{Asset: row.Identifier, Kind: row.Kind, Finding: f, Source: "scanner"}
		if f.CVE != "" {
			if err := apply(&r, &in); err != nil {
				return nil, err
			}
		}
		r.Input, r.Result = in, Score(in)
		out = append(out, r)
	}

	if withMatches {
		matched, err := store.ListMatched(ctx, tx)
		if err != nil {
			return nil, err
		}
		for _, m := range matched {
			f := Finding{
				Template: "software: " + strings.TrimSpace(m.Software+" "+m.Version),
				CVE:      m.CVE, Raw: m.Reason,
			}
			in := Input{CVE: m.CVE, Criticality: m.Criticality, Match: m.Tier, MatchConfidence: m.Confidence}
			r := Ranked{Asset: m.Identifier, Kind: m.Kind, Finding: f, Source: "match"}
			if err := apply(&r, &in); err != nil {
				return nil, err
			}
			r.Finding.Severity = severityOfScore(in.CVSS)
			in.Severity = r.Finding.Severity
			r.Input, r.Result = in, Score(in)
			out = append(out, r)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Result.Score != b.Result.Score {
			return a.Result.Score > b.Result.Score
		}
		if a.Asset != b.Asset {
			return a.Asset < b.Asset
		}
		return a.Finding.Template < b.Finding.Template
	})
	return out, nil
}

// severityOfScore names the CVSS band a score falls in, which is what a scanner
// would have called it. A CVE with no score is "unknown", not "info".
func severityOfScore(score *float32) string {
	switch {
	case score == nil:
		return "unknown"
	case *score >= 9:
		return "critical"
	case *score >= 7:
		return "high"
	case *score >= 4:
		return "medium"
	case *score > 0:
		return "low"
	}
	return "info"
}
