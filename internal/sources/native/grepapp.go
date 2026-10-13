package native

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

// GrepApp searches grep.app's index of public code for mentions of a domain, surfacing
// the repositories that reference the target — configs, client code and integrations
// that often carry endpoints or hardcoded hosts. It is passive and needs no key.
type GrepApp struct {
	Client  Doer
	BaseURL string
}

// NewGrepApp returns a grep.app source.
func NewGrepApp() *GrepApp {
	return &GrepApp{Client: &http.Client{Timeout: 20 * time.Second}, BaseURL: "https://grep.app"}
}

// Capability marks it passive, consuming a domain and producing repositories.
func (g *GrepApp) Capability() sources.Capability {
	return sources.Capability{
		Name:     "passive/grepapp",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeRepository},
		Passive:  true,
		CacheTTL: 24 * time.Hour,
		Cost:     1,
	}
}

// Available is always true; grep.app needs no credentials.
func (g *GrepApp) Available(sources.Env) bool { return true }

// Collect queries grep.app for the domain and records each repository that mentions it.
func (g *GrepApp) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	u := strings.TrimRight(g.BaseURL, "/") + "/api/search?q=" + url.QueryEscape(in.Key)
	body, _ := getBody(ctx, g.Client, u, 2)
	if len(body) == 0 {
		return nil
	}
	var doc struct {
		Hits struct {
			Hits []struct {
				Repo struct {
					Raw string `json:"raw"`
				} `json:"repo"`
				Path struct {
					Raw string `json:"raw"`
				} `json:"path"`
			} `json:"hits"`
		} `json:"hits"`
	}
	// Best-effort: a malformed body parses to an empty result and emits nothing.
	_ = json.Unmarshal(body, &doc)

	self := sink.Entity(graph.TypeDomain, in.Key, in.Key)
	seen := map[string]struct{}{}
	for _, h := range doc.Hits.Hits {
		repo := strings.TrimSpace(h.Repo.Raw)
		if repo == "" || !strings.Contains(repo, "/") {
			continue
		}
		if _, dup := seen[repo]; dup {
			continue
		}
		seen[repo] = struct{}{}
		key := "github.com/" + repo
		r := sink.Entity(graph.TypeRepository, key, repo)
		sink.Fact(r, "mentions", in.Key, 0.6)
		if p := strings.TrimSpace(h.Path.Raw); p != "" {
			sink.Fact(r, "path", p, 0.5)
		}
		sink.Fact(self, "code_reference", repo, 0.6)
	}
	return nil
}
