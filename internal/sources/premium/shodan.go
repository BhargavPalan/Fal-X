// Package premium adapts the paid internet-scan engines (Shodan, Censys and their
// peers) as engine sources. Each needs an API key, read from the run's credentials
// and never from a flag or the command line; an engine whose key is absent declares
// itself unavailable and is skipped. The adapters share one shape so adding an engine
// is adding a parser, not a framework.
package premium

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// maxBody bounds a response read.
const maxBody = 32 << 20

// Doer is the subset of *http.Client the adapters need, for testing against a fake.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// keyShodan is the credential name the Shodan adapter reads from the environment.
const keyShodan = "shodan"

// Shodan reads Shodan's host API for an IP: its open ports with product and version
// banners, the CPEs and CVEs Shodan already observed, and the hostnames it has seen.
// It is passive (Shodan scanned the target, this run does not) and needs a key.
type Shodan struct {
	Client  Doer
	BaseURL string
}

// NewShodan returns a Shodan adapter with a bounded client.
func NewShodan() *Shodan {
	return &Shodan{Client: &http.Client{Timeout: 20 * time.Second}, BaseURL: "https://api.shodan.io"}
}

// Capability marks it passive and key-gated, consuming an IP.
func (s *Shodan) Capability() sources.Capability {
	return sources.Capability{
		Name:      "premium/shodan",
		Consumes:  []graph.EntityType{graph.TypeIP},
		Produces:  []graph.EntityType{graph.TypeService, graph.TypeHost},
		Passive:   true,
		NeedsAuth: true,
		CacheTTL:  24 * time.Hour,
		Cost:      1,
	}
}

// Available reports whether a Shodan key is present.
func (s *Shodan) Available(env sources.Env) bool { return env.Keys[keyShodan] != "" }

// shodanHost is the subset of Shodan's host response the adapter reads.
type shodanHost struct {
	Hostnames []string `json:"hostnames"`
	Vulns     []string `json:"vulns"`
	Org       string   `json:"org"`
	Data      []struct {
		Port    int      `json:"port"`
		Product string   `json:"product"`
		Version string   `json:"version"`
		CPE     []string `json:"cpe"`
	} `json:"data"`
}

// Collect reads the IP's Shodan record. An IP Shodan has not seen (a 404) is not an
// error.
func (s *Shodan) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	key := sources.EnvFromContext(ctx).Keys[keyShodan]
	if key == "" {
		return nil
	}
	u := strings.TrimRight(s.BaseURL, "/") + "/shodan/host/" + url.PathEscape(in.Key) + "?key=" + url.QueryEscape(key)
	body := s.get(ctx, u)
	if len(body) == 0 {
		return nil
	}
	// Best-effort: a malformed body parses to an empty record and emits nothing.
	var doc shodanHost
	_ = json.Unmarshal(body, &doc)

	self := sink.Entity(graph.TypeIP, in.Key, in.Key)
	if doc.Org != "" {
		sink.Fact(self, "org", doc.Org, 0.8)
	}
	for _, d := range doc.Data {
		if d.Port <= 0 {
			continue
		}
		addr := net.JoinHostPort(in.Key, strconv.Itoa(d.Port))
		svc := sink.Entity(graph.TypeService, addr, addr)
		sink.Edge(self, svc, graph.RelHosts, 0.9)
		sink.Fact(svc, "port", strconv.Itoa(d.Port), 0.9)
		if prod := strings.TrimSpace(d.Product + " " + d.Version); prod != "" {
			sink.Fact(svc, "tech", prod, 0.8)
		}
		for _, cpe := range d.CPE {
			if cpe = strings.TrimSpace(cpe); cpe != "" {
				sink.Fact(svc, "cpe", cpe, 0.8)
			}
		}
	}
	for _, name := range doc.Hostnames {
		h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if isHostname(h) {
			sink.Entity(graph.TypeHost, h, h)
		}
	}
	for _, v := range doc.Vulns {
		if strings.HasPrefix(v, "CVE-") {
			// A CVE Shodan attributes to this IP is a finding; its severity is filled in
			// by intelligence enrichment, so it is stored with an unknown severity.
			sink.Fact(self, "finding", "unknown shodan "+v, 0.7)
		}
	}
	return nil
}

// get issues one authenticated GET and returns the body on 200, or nil.
func (s *Shodan) get(ctx context.Context, rawURL string) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return body
}

// isHostname reports whether s is a plausible DNS hostname.
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
