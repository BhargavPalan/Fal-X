package native

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Excavation mines an HTTP response body for the things recon cares about: hostnames
// of the same estate (new subdomains referenced but never resolved), contact emails,
// and high-confidence secret tokens an application accidentally served. It runs on the
// body the HTTP probe already fetched, so it costs no extra request.

// hostInBody matches FQDN-shaped tokens so same-domain hostnames can be lifted out of
// HTML and inline JavaScript.
var hostInBody = regexp.MustCompile(`[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+`)

// secretPattern is a credential shape worth reporting. The patterns are chosen to be
// specific enough that a match is almost certainly a real key, so a page that serves
// one is flagged without drowning the report in false positives.
type secretPattern struct {
	name string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"aws-access-key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"google-api-key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"slack-token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`)},
	{"github-token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`)},
	{"stripe-live-key", regexp.MustCompile(`sk_live_[0-9A-Za-z]{24,}`)},
	{"private-key-block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}`)},
	{"google-oauth-token", regexp.MustCompile(`ya29\.[0-9A-Za-z_\-]{20,}`)},
}

// excavate mines a body and emits what it finds onto the host and the serving URL.
// registeredDomain scopes the hostnames so only the estate's own names are emitted,
// not every external link on the page.
func excavate(body []byte, self, onURL graph.Ref, host string, sink sources.Sink) {
	text := string(body)
	rd := registeredDomain(host)

	seenHost := map[string]struct{}{}
	for _, m := range hostInBody.FindAllString(text, -1) {
		name := strings.ToLower(m)
		if name == host || !isHostname(name) {
			continue
		}
		// Only lift names within the same registrable domain, so mining a page does not
		// pull in every third party it links to.
		if rd == "" || (name != rd && !strings.HasSuffix(name, "."+rd)) {
			continue
		}
		if _, dup := seenHost[name]; dup || len(seenHost) >= 50 {
			continue
		}
		seenHost[name] = struct{}{}
		sink.Entity(graph.TypeHost, name, name)
	}

	for _, addr := range uniqueEmails(body) {
		sink.Entity(graph.TypeEmail, addr, addr)
		sink.Fact(self, "email", addr, 0.7)
	}

	mineAnalytics(text, self, sink)

	for _, s := range secretPatterns {
		if loc := s.re.FindString(text); loc != "" {
			// The secret itself is never stored; only its type and a short, redacted
			// fingerprint, so the finding is actionable without leaking the credential.
			key := "secret:" + s.name + ":" + redact(loc)
			cred := sink.Entity(graph.TypeCredential, key, s.name)
			sink.Edge(onURL, cred, graph.RelLeaks, 0.8)
			sink.Fact(self, "finding", "high leaked-secret "+s.name, 0.8)
			sink.Fact(onURL, "exposure", "leaked_secret", 0.8)
		}
	}
}

// analyticsRes extract the tracking identifiers that tie sibling sites to one operator:
// a shared Google Analytics/GA4/Tag-Manager or Facebook pixel id is a strong
// same-owner signal the correlation pass pivots on.
var analyticsRes = []*regexp.Regexp{
	regexp.MustCompile(`UA-\d{4,10}-\d{1,4}`),
	regexp.MustCompile(`G-[A-Z0-9]{8,12}`),
	regexp.MustCompile(`GTM-[A-Z0-9]{5,8}`),
}

var fbPixelRe = regexp.MustCompile(`fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]`)

// mineAnalytics emits an analytics_id fact for each distinct tracking id in the body.
func mineAnalytics(text string, self graph.Ref, sink sources.Sink) {
	seen := map[string]struct{}{}
	add := func(id string) {
		if id == "" {
			return
		}
		if _, dup := seen[id]; dup || len(seen) >= 20 {
			return
		}
		seen[id] = struct{}{}
		sink.Fact(self, "analytics_id", id, 0.7)
	}
	for _, re := range analyticsRes {
		for _, m := range re.FindAllString(text, -1) {
			add(m)
		}
	}
	for _, m := range fbPixelRe.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			add("fb:" + m[1])
		}
	}
}

// redact keeps only enough of a secret to identify it in a report without disclosing
// it: a short prefix and the length.
func redact(s string) string {
	prefix := s
	if len(prefix) > 4 {
		prefix = prefix[:4]
	}
	return fmt.Sprintf("%s…(%d)", prefix, len(s))
}

// registeredDomain approximates the registrable domain as the last two labels. It is a
// heuristic (no public-suffix list), good enough to scope same-estate hostnames and
// deliberately conservative: on a multi-part TLD it keeps more, never fewer, names out.
func registeredDomain(host string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(host, ".")), ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
