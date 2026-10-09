// Package prioritize ranks findings by how urgently they need attention, and says
// why.
//
// The score is deliberately simple and fully attributed: every point comes from a
// named signal with a plain-language reason, the reasons add up to the score, and
// a signal that is missing is stated rather than silently skipped. A ranking that
// cannot show its working is not worth trusting, so the requirement is exactly that:
// given any finding, print the full derivation.
//
// The decision is an SSVC-style Track, Attend or Act. It is a simplified
// reading, not the CISA SSVC decision tree: it uses only the signals Fal-X has
// (scanner severity, CISA KEV, EPSS, CVSS, operator-set criticality). Exposure is
// not assessed and is reported as such.
package prioritize

import (
	"fmt"
	"math"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/intel"
)

// The decisions, in increasing urgency.
const (
	Track  = "Track"  // note it, review on the normal cycle
	Attend = "Attend" // prioritise above routine work
	Act    = "Act"    // known exploited in the wild: act now
)

// Input is everything the scorer knows about one finding.
type Input struct {
	// Severity is the scanner's rating: critical, high, medium, low, info or unknown.
	Severity string
	// CVE is the CVE the finding names, if any. Intelligence only exists for
	// findings that name one.
	CVE string
	// KEV is true when the CVE is in CISA's Known Exploited Vulnerabilities list.
	KEV bool
	// Ransomware is true when KEV records ransomware campaign use.
	Ransomware bool
	// EPSS and EPSSPercentile are nil when no score is known, which is different
	// from a score of zero.
	EPSS           *float32
	EPSSPercentile *float32
	// CVSS is the base score from NVD, nil when it has not been fetched.
	// CVSSVersion is the scale it is on ("3.1", "4.0").
	CVSS        *float32
	CVSSVersion string
	// Criticality is the operator's rating of the asset, 0 (unset) to 100.
	Criticality int
}

// Reason is one attributed contribution to a score.
type Reason struct {
	Signal string
	Points int
	Detail string
}

// Result is a score with its derivation.
type Result struct {
	Score    int
	Decision string
	Why      []Reason
}

// severityPoints is the base for each scanner severity.
var severityPoints = map[string]int{
	"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 2, "unknown": 5,
}

// Score ranks one finding. The reasons always sum to the score.
func Score(in Input) Result {
	var r Result
	add := func(signal string, points int, detail string) {
		r.Why = append(r.Why, Reason{Signal: signal, Points: points, Detail: detail})
	}

	sev := strings.ToLower(strings.TrimSpace(in.Severity))
	pts, ok := severityPoints[sev]
	if !ok {
		sev, pts = "unknown", severityPoints["unknown"]
	}
	add("scanner severity", pts, "the scanner rated it "+sev)

	switch {
	case in.CVE == "":
		add("CISA KEV", 0, "the finding names no CVE, so there is no exploitation intelligence to apply")
	case in.KEV:
		add("CISA KEV", 40, in.CVE+" is on CISA's Known Exploited Vulnerabilities list")
		if in.Ransomware {
			add("ransomware use", 10, "KEV records it as used in ransomware campaigns")
		}
	default:
		add("CISA KEV", 0, in.CVE+" is not on CISA's Known Exploited Vulnerabilities list")
	}

	if in.CVE != "" {
		if in.EPSS != nil {
			p := int(math.Round(float64(*in.EPSS) * 30))
			detail := fmt.Sprintf("probability %.4f of exploitation in the next 30 days", *in.EPSS)
			if in.EPSSPercentile != nil {
				detail += fmt.Sprintf(" (%.1f%% percentile)", *in.EPSSPercentile*100)
			}
			add("EPSS", p, detail)
		} else {
			add("EPSS", 0, "no EPSS score is known for "+in.CVE)
		}

		if in.CVSS != nil {
			add("CVSS", int(math.Round(float64(*in.CVSS)/10*15)),
				fmt.Sprintf("NVD base score %.1f on CVSS v%s", *in.CVSS, in.CVSSVersion))
		} else {
			add("CVSS", 0, "no CVSS score has been fetched for "+in.CVE+" (run: fal-x intel enrich)")
		}
	}

	if in.Criticality > 0 {
		c := min(in.Criticality, 100)
		add("asset criticality", int(math.Round(float64(c)/100*10)),
			fmt.Sprintf("the operator rated this asset %d out of 100", c))
	} else {
		add("asset criticality", 0, "the operator has not rated this asset")
	}

	add("exposure", 0, "internet exposure is not assessed")

	total := 0
	for _, x := range r.Why {
		total += x.Points
	}
	if total > 100 {
		// Cap visibly, so the reasons still add up to the score.
		add("cap", 100-total, "scores are capped at 100")
		total = 100
	}
	r.Score = total

	switch {
	case in.KEV:
		r.Decision = Act
	case in.EPSS != nil && *in.EPSS >= 0.5, total >= 50:
		r.Decision = Attend
	default:
		r.Decision = Track
	}
	return r
}

// Finding is a scanner finding as stored on an asset.
type Finding struct {
	Severity string
	// Template is the scanner template, with its matcher when it has one.
	Template string
	// CVE is the first CVE the finding names, if any.
	CVE string
	// Raw is the stored value, kept so nothing is lost to parsing.
	Raw string
}

// ParseFinding reads the value `asset import` stores for a finding:
//
//	<severity> <template>[:matcher] [detail]
//
// A value that does not fit is kept with severity "unknown" rather than dropped.
func ParseFinding(value string) Finding {
	value = strings.TrimSpace(value)
	f := Finding{Severity: "unknown", Raw: value}
	if value == "" {
		return f
	}
	fields := strings.Fields(value)
	f.Severity = strings.ToLower(fields[0])
	if len(fields) > 1 {
		f.Template = fields[1]
	}
	if ids := intel.CVEsIn(value); len(ids) > 0 {
		f.CVE = ids[0]
	}
	return f
}
