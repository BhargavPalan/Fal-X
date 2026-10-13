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
// reading, not the CISA SSVC decision tree: it uses the signals Fal-X has (scanner
// severity, CISA KEV, EPSS, CVSS, operator-set criticality, and the exposure class of
// a finding — a confirmed takeover or leaked secret is weighted for its inherent
// impact, not only the severity word the source stamped on it).
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
	// Match is empty for a scanner finding. For a software match it is the tier
	// (affected, conditional, possible or unverified) and MatchConfidence the
	// matcher's confidence, so an inference ranks below a finding a scanner confirmed.
	Match           string
	MatchConfidence string
	// Exposure is the finding's template/class (e.g. "subdomain-takeover-confirmed",
	// "leaked-secret", "open-cloud-bucket"), used to weight its inherent impact.
	Exposure string
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
			// EPSS is a probability in [0,1]; clamp so a malformed feed cannot inflate
			// the score past the documented weight.
			epss := float64(*in.EPSS)
			if epss < 0 {
				epss = 0
			} else if epss > 1 {
				epss = 1
			}
			p := int(math.Round(epss * 30))
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

	ep, ed := exposurePoints(in.Exposure)
	add("exposure", ep, ed)
	if in.Match != "" {
		points, detail := matchAdjustment(in.Match, in.MatchConfidence)
		add("match confidence", points, detail)
	}

	total := 0
	for _, x := range r.Why {
		total += x.Points
	}
	if total > 100 {
		// Cap visibly, so the reasons still add up to the score.
		add("cap", 100-total, "scores are capped at 100")
		total = 100
	}
	if total < 0 {
		add("floor", -total, "scores are not negative")
		total = 0
	}
	r.Score = total

	switch {
	case in.KEV && (in.Match == "" || in.Match == "affected"):
		r.Decision = Act
	case in.KEV:
		// Known exploited, but applicability is not confirmed: either only the product
		// is known and not that this version is affected, or the match is conditional
		// on something the matcher explicitly did not verify. Not yet a reason to act.
		r.Decision = Attend
	case in.EPSS != nil && *in.EPSS >= 0.5, total >= 50:
		r.Decision = Attend
	default:
		r.Decision = Track
	}
	return r
}

// exposureRule maps an exposure template substring to the impact points it adds and a
// reason, ordered most severe first so the strongest match wins.
type exposureRule struct {
	match  string
	points int
	detail string
}

var exposureRules = []exposureRule{
	{"aws-credentials", 25, "an exposed cloud credential grants direct access"},
	{"leaked-secret", 25, "a live secret was served in a response or repository"},
	{"verified-secret", 25, "a verified live credential was found in source"},
	{"takeover", 25, "a confirmed subdomain takeover lets an attacker serve content as this host"},
	{"exposed-git", 20, "a web-exposed .git can reconstruct source and secrets"},
	{"exposed-env", 20, "an exposed .env typically holds credentials"},
	{"open-cloud-bucket", 20, "a publicly listable bucket exposes its objects"},
	{"origin-ip-exposed", 15, "the origin behind the CDN/WAF is reachable directly, bypassing it"},
	{"zone-transfer", 15, "an open AXFR discloses the whole zone"},
	{"access-control-bypass", 15, "a forbidden resource was reached by a bypass"},
	{"source-backup", 15, "an exposed source backup discloses application code"},
	{"dangling-cname", 12, "a dangling CNAME is a takeover candidate"},
	{"cors-origin-reflection-with-credentials", 12, "CORS reflects any origin with credentials"},
	{"spring-actuator", 12, "an exposed actuator leaks configuration and secrets"},
	{"breach-exposure", 8, "the organization appears in a known breach"},
	{"graphql-introspection", 8, "introspection exposes the full API schema"},
	{"phpinfo", 6, "phpinfo discloses configuration and paths"},
	{"api-spec", 5, "a published API spec enumerates endpoints and parameters"},
	{"email-spoofable", 5, "weak SPF/DMARC allows sender spoofing"},
	{"certificate", 5, "a certificate weakness (expired, self-signed or weak signature)"},
	{"cert", 5, "a certificate weakness (expired, self-signed or weak signature)"}, // nuclei abbreviates "certificate"
}

// exposurePoints weights a finding by the inherent impact of its exposure class, so a
// confirmed takeover or leaked secret outranks a low-severity finding regardless of the
// severity word the source stamped on it. The class is matched on whole hyphen-
// delimited tokens, not as a loose substring, so "takeover" matches
// "subdomain-takeover-confirmed" but a negated or unrelated template (e.g. a nuclei
// id that merely contains the letters) does not score the exposure's points.
func exposurePoints(template string) (int, string) {
	t := strings.ToLower(strings.TrimSpace(template))
	if t == "" {
		return 0, "the finding carries no exposure class"
	}
	// A negated class is not an exposure.
	if strings.Contains(t, "false-positive") || strings.HasPrefix(t, "no-") || strings.HasPrefix(t, "not-") {
		return 0, "the finding's class is negated, so it carries no exposure weight"
	}
	toks := strings.Split(t, "-")
	for _, r := range exposureRules {
		if hyphenSublist(toks, strings.Split(r.match, "-")) {
			return r.points, r.detail
		}
	}
	return 0, "the finding's class carries no extra exposure weight"
}

// hyphenSublist reports whether needle appears as a contiguous run of whole tokens in
// hay (both already split on "-").
func hyphenSublist(hay, needle []string) bool {
	if len(needle) == 0 || len(needle) > len(hay) {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// matchAdjustment is what a software match gives up for being inferred from a
// banner and not confirmed by a scanner.
func matchAdjustment(tier, confidence string) (int, string) {
	switch tier {
	case "affected":
		if confidence == "high" {
			return 0, "the observed version is inside a range NVD lists as vulnerable"
		}
		return -5, "the version matches, but the banner may come from a distribution that backports fixes"
	case "conditional":
		return -10, "NVD lists this only together with something else, which has not been checked"
	case "possible":
		return -15, "the product is present but its version is not known"
	default:
		return -20, "the product was guessed from its name"
	}
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
