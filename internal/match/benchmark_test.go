package match

import "testing"

// benchCase is one hand-verified fact: whether a version of a product is inside what
// NVD lists as vulnerable for a CVE. The ranges are the ones NVD publishes for these
// well-known CVEs, written out here so the test needs no database and no feed.
type benchCase struct {
	cve, product, version string
	rows                  []cpeRow
	want                  bool
}

func exact(vs ...string) []cpeRow {
	var out []cpeRow
	for _, v := range vs {
		out = append(out, cpeRow{version: v})
	}
	return out
}

func span(r Range) []cpeRow { return []cpeRow{{version: "*", rng: r}} }

var benchmark = []benchCase{
	// Apache HTTP Server path traversal: exactly 2.4.49.
	{"CVE-2021-41773", "apache", "2.4.49", exact("2.4.49"), true},
	{"CVE-2021-41773", "apache", "2.4.50", exact("2.4.49"), false},
	{"CVE-2021-41773", "apache", "2.4.7", exact("2.4.49"), false},
	// Its incomplete fix: 2.4.49 and 2.4.50.
	{"CVE-2021-42013", "apache", "2.4.50", exact("2.4.49", "2.4.50"), true},
	{"CVE-2021-42013", "apache", "2.4.51", exact("2.4.49", "2.4.50"), false},
	// mod_proxy SSRF: 2.4.0 up to 2.4.48.
	{"CVE-2021-40438", "apache", "2.4.48", span(Range{StartIncluding: "2.4.0", EndIncluding: "2.4.48"}), true},
	{"CVE-2021-40438", "apache", "2.4.49", span(Range{StartIncluding: "2.4.0", EndIncluding: "2.4.48"}), false},
	{"CVE-2021-40438", "apache", "2.4.10", span(Range{StartIncluding: "2.4.0", EndIncluding: "2.4.48"}), true},
	// Heartbleed: OpenSSL 1.0.1 through 1.0.1f, listed one by one.
	{"CVE-2014-0160", "openssl", "1.0.1f", exact("1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"), true},
	{"CVE-2014-0160", "openssl", "1.0.1g", exact("1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"), false},
	{"CVE-2014-0160", "openssl", "1.0.2", exact("1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"), false},
	// OpenSSH username enumeration: up to and including 7.7.
	{"CVE-2018-15473", "openssh", "7.7", span(Range{EndIncluding: "7.7"}), true},
	{"CVE-2018-15473", "openssh", "6.6.1p1", span(Range{EndIncluding: "7.7"}), true},
	{"CVE-2018-15473", "openssh", "7.8", span(Range{EndIncluding: "7.7"}), false},
	{"CVE-2018-15473", "openssh", "8.9p1", span(Range{EndIncluding: "7.7"}), false},
	// nginx resolver overwrite: 0.6.18 up to, not including, 1.20.1.
	{"CVE-2021-23017", "nginx", "1.18.0", span(Range{StartIncluding: "0.6.18", EndExcluding: "1.20.1"}), true},
	{"CVE-2021-23017", "nginx", "1.20.1", span(Range{StartIncluding: "0.6.18", EndExcluding: "1.20.1"}), false},
	{"CVE-2021-23017", "nginx", "0.5.0", span(Range{StartIncluding: "0.6.18", EndExcluding: "1.20.1"}), false},
	{"CVE-2021-23017", "nginx", "1.9.10", span(Range{StartIncluding: "0.6.18", EndExcluding: "1.20.1"}), true},
	// Tomcat Ghostcat, three ranges across release lines.
	{"CVE-2020-1938", "tomcat", "9.0.30", []cpeRow{
		{version: "*", rng: Range{StartIncluding: "9.0.0", EndExcluding: "9.0.31"}},
		{version: "*", rng: Range{StartIncluding: "8.5.0", EndExcluding: "8.5.51"}},
		{version: "*", rng: Range{StartIncluding: "7.0.0", EndExcluding: "7.0.100"}},
	}, true},
	{"CVE-2020-1938", "tomcat", "9.0.31", []cpeRow{
		{version: "*", rng: Range{StartIncluding: "9.0.0", EndExcluding: "9.0.31"}},
		{version: "*", rng: Range{StartIncluding: "8.5.0", EndExcluding: "8.5.51"}},
		{version: "*", rng: Range{StartIncluding: "7.0.0", EndExcluding: "7.0.100"}},
	}, false},
	{"CVE-2020-1938", "tomcat", "7.0.99", []cpeRow{
		{version: "*", rng: Range{StartIncluding: "9.0.0", EndExcluding: "9.0.31"}},
		{version: "*", rng: Range{StartIncluding: "7.0.0", EndExcluding: "7.0.100"}},
	}, true},
	// A product NVD lists for every version.
	{"CVE-2000-0001", "anything", "9.9.9", span(Range{}), true},
	// A "not applicable" entry never matches a version.
	{"CVE-2000-0002", "anything", "1.0", exact("-"), false},
}

func matchesAny(version string, rows []cpeRow) bool {
	for _, r := range rows {
		if _, ok := applies(version, r); ok {
			return true
		}
	}
	return false
}

// TestBenchmarkPrecisionAndRecall pins the version logic against hand-verified
// cases. A wrong "affected" is a false alarm that teaches people to ignore the tool,
// and a wrong "not affected" hides a real exposure, so neither is allowed here.
func TestBenchmarkPrecisionAndRecall(t *testing.T) {
	var tp, fp, fn, tn int
	for _, c := range benchmark {
		got := matchesAny(c.version, c.rows)
		switch {
		case got && c.want:
			tp++
		case got && !c.want:
			fp++
			t.Errorf("%s %s %s: reported affected, but it is not", c.cve, c.product, c.version)
		case !got && c.want:
			fn++
			t.Errorf("%s %s %s: reported not affected, but it is", c.cve, c.product, c.version)
		default:
			tn++
		}
	}
	t.Logf("benchmark: %d cases, tp=%d fp=%d fn=%d tn=%d", len(benchmark), tp, fp, fn, tn)
	if fp != 0 || fn != 0 {
		t.Fatalf("precision/recall below 100%% on the labelled set: fp=%d fn=%d", fp, fn)
	}
}
