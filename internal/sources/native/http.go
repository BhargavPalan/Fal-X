package native

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// titleRe extracts the first HTML <title>. It is deliberately forgiving of
// attributes and case.
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// maxProbeBody bounds how much of a page is read to find its title.
const maxProbeBody = 256 << 10

// HTTPProbe probes a host over HTTPS then HTTP and records what the server says
// about itself: the Server header (directly matchable to a CVE), the page title,
// and the status. It is active: it connects to the target.
type HTTPProbe struct {
	Client *http.Client
}

// NewHTTPProbe returns a probe with a bounded client that does not verify TLS
// certificates, because a recon probe must still fingerprint a host serving a
// self-signed or expired certificate.
func NewHTTPProbe() *HTTPProbe {
	return &HTTPProbe{Client: &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // recon must probe hosts with invalid certs
		},
	}}
}

// Capability marks the probe active and consuming a host.
func (p *HTTPProbe) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/http",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{graph.TypeURL},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; the probe uses the standard library.
func (p *HTTPProbe) Available(sources.Env) bool { return true }

// Collect probes the host, stopping at the first scheme that answers.
func (p *HTTPProbe) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	host := in.Key
	self := sink.Entity(graph.TypeHost, host, host)
	for _, u := range []string{"https://" + host, "http://" + host} {
		if p.emit(ctx, u, host, self, sink) {
			return nil
		}
	}
	return nil
}

// emit probes one URL and records what it found, returning whether the host
// answered.
func (p *HTTPProbe) emit(ctx context.Context, rawURL, host string, self graph.Ref, sink sources.Sink) bool {
	r, err := p.probe(ctx, rawURL)
	if err != nil {
		return false
	}
	u := sink.Entity(graph.TypeURL, r.finalURL, r.finalURL)
	sink.Edge(self, u, graph.RelServesURL, 1.0)
	sink.Fact(u, "status", r.status, 1.0)
	if r.title != "" {
		sink.Fact(u, "title", r.title, 0.9)
	}
	if r.contentType != "" {
		sink.Fact(u, "content_type", r.contentType, 0.9)
	}
	if r.location != "" {
		sink.Fact(u, "redirect", r.location, 0.9)
	}
	if r.server != "" {
		// The Server header is software evidence about the host, so it is recorded
		// on the host under the key the matcher reads.
		sink.Fact(self, "server", r.server, 1.0)
	}
	// Software-revealing headers and session-cookie names are matcher evidence, so
	// they are recorded under the "tech" key the matcher reads.
	for _, t := range r.tech {
		sink.Fact(self, "tech", t, 0.9)
	}
	// Which hardening headers the server sets is posture worth reporting.
	for _, h := range r.secHeaders {
		sink.Fact(u, "sec_header", h, 1.0)
	}
	// Mine the body (and the CSP allow-list) for same-estate hostnames, emails and
	// exposed secrets — no extra request, since the body is already in hand.
	scan := r.body
	if r.csp != "" {
		scan = append(append([]byte{}, r.body...), " "+r.csp...)
	}
	excavate(scan, self, u, host, sink)
	return true
}

type probeResult struct {
	status, server, title, finalURL, contentType, location, csp string
	body                                                        []byte
	tech                                                        []string // software-revealing header/cookie evidence
	secHeaders                                                  []string // hardening headers the server sets
}

// techHeaders are response headers whose value names the software or framework
// behind the host — direct, matchable version evidence.
var techHeaders = []string{
	"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
	"X-Generator", "X-Drupal-Dynamic-Cache", "X-Shopify-Stage", "X-Served-By",
}

// securityHeaders are the hardening response headers whose presence is recorded as
// the host's posture.
var securityHeaders = []string{
	"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
	"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
}

func (p *HTTPProbe) probe(ctx context.Context, rawURL string) (probeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return probeResult{}, err
	}
	req.Header.Set("User-Agent", "fal-x")
	resp, err := p.Client.Do(req)
	if err != nil {
		return probeResult{}, err
	}
	defer resp.Body.Close()

	out := probeResult{
		status:      strconv.Itoa(resp.StatusCode),
		server:      strings.TrimSpace(resp.Header.Get("Server")),
		finalURL:    resp.Request.URL.String(),
		contentType: strings.TrimSpace(resp.Header.Get("Content-Type")),
		location:    strings.TrimSpace(resp.Header.Get("Location")),
		csp:         strings.TrimSpace(resp.Header.Get("Content-Security-Policy")),
	}
	for _, h := range techHeaders {
		if v := strings.TrimSpace(resp.Header.Get(h)); v != "" {
			out.tech = append(out.tech, v)
		}
	}
	// Only the cookie name is read; a cookie value may be a session token and is never
	// stored.
	for _, c := range resp.Cookies() {
		if t := cookieTech(c.Name); t != "" {
			out.tech = append(out.tech, t)
		}
	}
	for _, h := range securityHeaders {
		if resp.Header.Get(h) != "" {
			out.secHeaders = append(out.secHeaders, h)
		}
	}
	out.body, _ = io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	if m := titleRe.FindSubmatch(out.body); m != nil {
		out.title = strings.Join(strings.Fields(string(m[1])), " ")
	}
	return out, nil
}

// cookieTech maps a well-known session-cookie name to the platform that sets it, so a
// host's stack is identified even when it hides its Server header. An unknown name
// returns an empty string.
func cookieTech(name string) string {
	switch strings.ToUpper(name) {
	case "PHPSESSID":
		return "PHP"
	case "JSESSIONID":
		return "Java"
	case "ASP.NET_SESSIONID", "ASPXAUTH", "__REQUESTVERIFICATIONTOKEN":
		return "ASP.NET"
	case "ASPSESSIONID":
		return "ASP"
	case "CFID", "CFTOKEN":
		return "ColdFusion"
	case "LARAVEL_SESSION":
		return "Laravel"
	case "CAKEPHP":
		return "CakePHP"
	default:
		return ""
	}
}
