package premium

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Hunter reads hunter.io's domain search: the corporate email addresses and the named
// people behind them, the start of the human attack surface (phishing targets,
// credential-reuse pivots). It is passive and key-gated.
type Hunter struct {
	Client  Doer
	BaseURL string
}

// NewHunter returns a hunter.io adapter.
func NewHunter() *Hunter {
	return &Hunter{Client: &http.Client{Timeout: 20 * time.Second}, BaseURL: "https://api.hunter.io"}
}

// Capability marks it passive and key-gated, consuming a domain.
func (h *Hunter) Capability() sources.Capability {
	return sources.Capability{
		Name:      "premium/hunter",
		Consumes:  []graph.EntityType{graph.TypeDomain},
		Produces:  []graph.EntityType{graph.TypeEmail, graph.TypePerson},
		Passive:   true,
		NeedsAuth: true,
		CacheTTL:  24 * time.Hour,
		Cost:      1,
	}
}

// Available reports whether a hunter.io key is present.
func (h *Hunter) Available(env sources.Env) bool { return env.Keys["hunter"] != "" }

// Collect reads the domain's emails and the people attached to them.
func (h *Hunter) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	key := keyFromContext(ctx, "hunter")
	if key == "" {
		return nil
	}
	u := strings.TrimRight(h.BaseURL, "/") + "/v2/domain-search?domain=" + url.QueryEscape(in.Key) +
		"&api_key=" + url.QueryEscape(key)
	body := authGet(ctx, h.Client, u, nil)
	if len(body) == 0 {
		return nil
	}
	var doc struct {
		Data struct {
			Emails []struct {
				Value     string `json:"value"`
				FirstName string `json:"first_name"`
				LastName  string `json:"last_name"`
				Position  string `json:"position"`
			} `json:"emails"`
		} `json:"data"`
	}
	_ = json.Unmarshal(body, &doc) // best-effort

	self := sink.Entity(graph.TypeDomain, in.Key, in.Key)
	for _, e := range doc.Data.Emails {
		addr := strings.ToLower(strings.TrimSpace(e.Value))
		if !emailRe.MatchString(addr) {
			continue
		}
		em := sink.Entity(graph.TypeEmail, addr, addr)
		sink.Fact(self, "email", addr, 0.8)
		if name := strings.TrimSpace(e.FirstName + " " + e.LastName); name != "" {
			p := sink.Entity(graph.TypePerson, strings.ToLower(name), name)
			sink.Edge(p, em, graph.RelHasEmail, 0.8)
			if e.Position != "" {
				sink.Fact(p, "position", e.Position, 0.7)
			}
		}
	}
	return nil
}
