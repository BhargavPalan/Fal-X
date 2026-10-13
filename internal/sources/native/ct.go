package native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// CT discovers subdomains from certificate transparency logs via crt.sh. It is
// passive (it queries a third party, never the target) and needs no key.
type CT struct {
	Client  Doer
	BaseURL string
}

// NewCT returns a CT source using crt.sh and a bounded HTTP client.
func NewCT() *CT {
	return &CT{Client: &http.Client{Timeout: 20 * time.Second}, BaseURL: "https://crt.sh"}
}

// Capability marks CT passive: it reads crt.sh, so it runs even in a passive scan.
func (c *CT) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/ct",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeHost},
		Passive:  true,
		CacheTTL: time.Hour,
		Cost:     1,
	}
}

// Available is always true; crt.sh needs no credentials.
func (c *CT) Available(sources.Env) bool { return true }

// Collect queries crt.sh for every certificate naming a subdomain of the input
// domain and emits each distinct name as a host.
func (c *CT) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	domain := in.Key
	url := fmt.Sprintf("%s/?q=%%25.%s&output=json", strings.TrimRight(c.BaseURL, "/"), domain)
	body, err := getBody(ctx, c.Client, url, 2)
	if err != nil {
		return err
	}
	// crt.sh sometimes returns an HTML error page under load. A response that is not
	// a JSON array is treated as no results; a malformed JSON array is a real error.
	if body = bytes.TrimSpace(body); len(body) == 0 || body[0] != '[' {
		return nil
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return err
	}

	self := sink.Entity(graph.TypeDomain, domain, domain)
	seen := map[string]struct{}{}
	for _, r := range rows {
		for name := range strings.SplitSeq(r.NameValue, "\n") {
			name = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*.")
			if name == "" || !isHostname(name) {
				continue
			}
			// Keep only names under the queried domain; crt.sh can return unrelated
			// SANs from a shared certificate.
			if name != domain && !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			h := sink.Entity(graph.TypeHost, name, name)
			sink.Edge(h, self, graph.RelSubdomainOf, 1.0)
		}
	}
	return nil
}

// isHostname reports whether s is a plausible DNS hostname: dotted, with labels of
// only letters, digits and hyphens.
func isHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			switch {
			case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '-':
			default:
				return false
			}
		}
	}
	return true
}
