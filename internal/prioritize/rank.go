package prioritize

import (
	"context"
	"database/sql"
	"sort"

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
}

// Rank scores every finding the tenant has, most urgent first. Ties break by
// asset and template so the order is stable between runs.
//
// It reads the intelligence from the same transaction. The intelligence tables are
// global, so a tenant's transaction can read them without leaving its own scope.
func Rank(ctx context.Context, tx *sql.Tx) ([]Ranked, error) {
	rows, err := store.ListFindings(ctx, tx)
	if err != nil {
		return nil, err
	}

	cache := map[string]*intel.Detail{}
	out := make([]Ranked, 0, len(rows))
	for _, row := range rows {
		f := ParseFinding(row.Value)
		in := Input{Severity: f.Severity, CVE: f.CVE, Criticality: row.Criticality}

		r := Ranked{Asset: row.Identifier, Kind: row.Kind, Finding: f}
		if f.CVE != "" {
			d, ok := cache[f.CVE]
			if !ok {
				if d, err = intel.Show(ctx, tx, f.CVE); err != nil {
					return nil, err
				}
				cache[f.CVE] = d
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
		}
		r.Input, r.Result = in, Score(in)
		out = append(out, r)
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
