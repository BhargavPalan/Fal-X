package native

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// corsProbeOrigin is the attacker-controlled origin reflected back by a misconfigured
// server.
const corsProbeOrigin = "https://falx-cors-probe.example"

// CORS checks a host's cross-origin resource sharing policy for the misconfigurations
// that let a malicious site read authenticated responses: reflecting an arbitrary
// Origin, allowing the null origin, or allowing any origin together with credentials.
// It is active: it sends one request with a crafted Origin header.
type CORS struct {
	Client Doer
}

// NewCORS returns a CORS prober with a bounded client.
func NewCORS() *CORS {
	return &CORS{Client: &http.Client{Timeout: 10 * time.Second}}
}

// Capability marks it active, consuming a host and producing findings.
func (c *CORS) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/cors",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{graph.TypeFinding},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; it uses the standard library.
func (c *CORS) Available(sources.Env) bool { return true }

// Collect sends a crafted Origin to the host and judges the ACAO/ACAC response.
func (c *CORS) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	host := in.Key
	for _, scheme := range []string{"https://", "http://"} {
		if sev, cls := c.check(ctx, scheme+host); cls != "" {
			self := sink.Entity(graph.TypeHost, host, host)
			sink.Fact(self, "finding", sev, 0.8)
			sink.Fact(self, "exposure", cls, 0.8)
			return nil
		}
	}
	return nil
}

// check returns a finding value and exposure class when the ACAO/ACAC response is
// unsafe, or empty strings otherwise.
func (c *CORS) check(ctx context.Context, rawURL string) (finding, class string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "fal-x")
	req.Header.Set("Origin", corsProbeOrigin)
	resp, err := c.Client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	_ = readBounded(resp.Body, 4<<10) // drain a little so the connection can be reused

	acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	acac := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")
	switch {
	case strings.EqualFold(acao, corsProbeOrigin):
		// The server echoes any origin: with credentials this is a full account-read
		// primitive, so it is the most severe form.
		if acac {
			return "high cors-origin-reflection-with-credentials", "cors_reflect_credentials"
		}
		return "medium cors-origin-reflection", "cors_reflect"
	case strings.EqualFold(acao, "null"):
		return "medium cors-null-origin-allowed", "cors_null"
	case acao == "*" && acac:
		return "medium cors-wildcard-with-credentials", "cors_wildcard_credentials"
	}
	return "", ""
}
