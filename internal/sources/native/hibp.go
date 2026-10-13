package native

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// HIBP reads Have I Been Pwned's public breach catalogue for a domain: the known
// breaches of that organisation, which signal exposed employee or customer credentials
// and password-reuse risk. The breaches endpoint needs no key. It is passive.
type HIBP struct {
	Client  Doer
	BaseURL string
}

// NewHIBP returns an HIBP source.
func NewHIBP() *HIBP {
	return &HIBP{Client: &http.Client{Timeout: 20 * time.Second}, BaseURL: "https://haveibeenpwned.com"}
}

// Capability marks it passive, consuming a domain and producing leak entities.
func (h *HIBP) Capability() sources.Capability {
	return sources.Capability{
		Name:     "passive/hibp",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeLeak, graph.TypeFinding},
		Passive:  true,
		CacheTTL: 24 * time.Hour,
		Cost:     1,
	}
}

// Available is always true; the breaches endpoint needs no credentials.
func (h *HIBP) Available(sources.Env) bool { return true }

// Collect reads the domain's breaches. A domain with none (a 404) is not an error.
func (h *HIBP) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	u := strings.TrimRight(h.BaseURL, "/") + "/api/v3/breaches?domain=" + url.QueryEscape(in.Key)
	body, _ := getBody(ctx, h.Client, u, 2)
	if len(body) == 0 {
		return nil
	}
	var breaches []struct {
		Name       string   `json:"Name"`
		Title      string   `json:"Title"`
		BreachDate string   `json:"BreachDate"`
		PwnCount   int      `json:"PwnCount"`
		DataClass  []string `json:"DataClasses"`
	}
	// Best-effort: a non-array body (an error page) parses to nothing.
	_ = json.Unmarshal(body, &breaches)

	self := sink.Entity(graph.TypeDomain, in.Key, in.Key)
	for _, b := range breaches {
		if b.Name == "" {
			continue
		}
		leak := sink.Entity(graph.TypeLeak, "hibp:"+b.Name, firstNonEmpty(b.Title, b.Name))
		sink.Fact(self, "finding", "medium breach-exposure "+b.Name, 0.7)
		sink.Fact(self, "exposure", "breach", 0.7)
		if b.BreachDate != "" {
			sink.Fact(leak, "breach_date", b.BreachDate, 0.8)
		}
		if b.PwnCount > 0 {
			sink.Fact(leak, "pwn_count", strconv.Itoa(b.PwnCount), 0.8)
		}
		if len(b.DataClass) > 0 {
			sink.Fact(leak, "data_classes", strings.Join(b.DataClass, ", "), 0.7)
		}
	}
	return nil
}
