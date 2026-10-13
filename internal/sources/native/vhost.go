package native

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// maxVhostBody bounds the body read when comparing a candidate against the catch-all;
// large enough that two distinct pages are rarely both truncated to the same length.
const maxVhostBody = 512 << 10

// vhostWords are candidate hostname labels for virtual hosts an estate commonly serves
// off DNS: the internal, staging and tooling apps that answer only to the right Host
// header on an IP that is otherwise a public site.
var vhostWords = []string{
	"dev", "development", "staging", "stage", "stg", "uat", "qa", "test", "testing",
	"preprod", "beta", "demo", "sandbox", "internal", "intranet", "corp", "admin",
	"portal", "dashboard", "api", "api-dev", "api-internal", "app", "old", "legacy",
	"backup", "vpn", "jenkins", "gitlab", "grafana", "kibana", "jira", "confluence",
}

// Vhost finds virtual hosts not present in DNS: it sends candidate Host headers to the
// server the input host already answers on, and reports those whose response differs
// from the server's catch-all — the signature of a distinct application served off DNS.
// It is active and heavy: one request per candidate.
type Vhost struct {
	Client Doer
}

// NewVhost returns the probe with a bounded client that does not follow redirects, so a
// redirect is itself a distinguishing response rather than being chased away.
func NewVhost() *Vhost {
	return &Vhost{Client: &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Capability marks it active and heavy, consuming a host and producing the virtual
// hosts it uncovers.
func (v *Vhost) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/vhost",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{graph.TypeHost},
		Passive:  false,
		Heavy:    true,
		Cost:     3,
	}
}

// Available is always true; it uses the standard library.
func (v *Vhost) Available(sources.Env) bool { return true }

// probe is a server's answer to one Host header.
type probe struct {
	status int
	length int
	ok     bool
}

// Collect probes the candidate virtual hosts against the host's own server.
func (v *Vhost) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	host := in.Key
	rd := registeredDomain(host)
	if rd == "" {
		return nil
	}
	base, ok := v.workingScheme(ctx, host)
	if !ok {
		return nil // the host serves no web
	}
	// The catch-all: what the server returns for a Host it does not know. A real virtual
	// host answers differently from this. If the baseline probe itself fails, there is
	// nothing to compare against, so every candidate would look distinct — abort rather
	// than fabricate virtual hosts from a zero-value baseline.
	baseline := v.request(ctx, base, "falx-vhost-baseline-9f3a2b1c."+rd)
	if !baseline.ok {
		return nil
	}
	self := sink.Entity(graph.TypeHost, host, host)
	for _, w := range vhostWords {
		cand := w + "." + rd
		if cand == host || !isHostname(cand) {
			continue
		}
		p := v.request(ctx, base, cand)
		if !distinctVhost(p, baseline) {
			continue
		}
		sink.Entity(graph.TypeHost, cand, cand)
		sink.Fact(self, "vhost", cand, 0.6)
	}
	return nil
}

// workingScheme returns the scheme+host that answers, trying HTTPS then HTTP.
func (v *Vhost) workingScheme(ctx context.Context, host string) (string, bool) {
	for _, scheme := range []string{"https://", "http://"} {
		base := scheme + host
		if v.request(ctx, base, host).ok {
			return base, true
		}
	}
	return "", false
}

// request sends GET base/ with an overridden Host header, so every candidate reaches the
// same server (the same IP) under a different virtual-host name.
func (v *Vhost) request(ctx context.Context, base, hostHeader string) probe {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return probe{}
	}
	req.Host = hostHeader
	req.Header.Set("User-Agent", "fal-x")
	resp, err := v.Client.Do(req)
	if err != nil {
		return probe{}
	}
	defer resp.Body.Close()
	// Read a generous bound so the length is a real signal: capping at a few KB would make
	// two different pages that both exceed the cap look identical in size.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxVhostBody))
	return probe{status: resp.StatusCode, length: len(body), ok: true}
}

// distinctVhost reports whether a candidate's response marks a real, distinct virtual
// host: it must carry an interesting status and differ from the catch-all in status or
// materially in size.
func distinctVhost(p, baseline probe) bool {
	if !p.ok || !interestingStatus(p.status) {
		return false
	}
	if p.status != baseline.status {
		return true
	}
	diff := p.length - baseline.length
	if diff < 0 {
		diff = -diff
	}
	return diff > 64
}

// interestingStatus is a status that indicates a served application (including one behind
// auth), as opposed to a plain not-found.
func interestingStatus(status int) bool {
	switch status {
	case http.StatusOK, http.StatusMovedPermanently, http.StatusFound,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
		http.StatusUnauthorized, http.StatusForbidden:
		return true
	default:
		return false
	}
}
