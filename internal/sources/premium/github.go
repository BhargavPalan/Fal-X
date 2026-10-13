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

// GitHub searches GitHub's code index for a domain, surfacing the repositories whose
// source mentions it — the integrations, infrastructure-as-code and client apps that
// so often carry endpoints, internal hosts and leaked secrets. It is passive and needs
// a GitHub token (unauthenticated code search is not allowed).
type GitHub struct {
	Client  Doer
	BaseURL string
}

// NewGitHub returns a GitHub code-search adapter.
func NewGitHub() *GitHub {
	return &GitHub{Client: &http.Client{Timeout: 20 * time.Second}, BaseURL: "https://api.github.com"}
}

// Capability marks it passive and key-gated, consuming a domain.
func (g *GitHub) Capability() sources.Capability {
	return sources.Capability{
		Name:      "premium/github",
		Consumes:  []graph.EntityType{graph.TypeDomain},
		Produces:  []graph.EntityType{graph.TypeRepository},
		Passive:   true,
		NeedsAuth: true,
		CacheTTL:  24 * time.Hour,
		Cost:      1,
	}
}

// Available reports whether a GitHub token is present.
func (g *GitHub) Available(env sources.Env) bool { return env.Keys["github"] != "" }

// Collect searches code for the domain and records each repository that mentions it.
func (g *GitHub) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	token := keyFromContext(ctx, "github")
	if token == "" {
		return nil
	}
	u := strings.TrimRight(g.BaseURL, "/") + "/search/code?per_page=50&q=" + url.QueryEscape("\""+in.Key+"\"")
	body := authGet(ctx, g.Client, u, map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/vnd.github+json",
	})
	if len(body) == 0 {
		return nil
	}
	var doc struct {
		Items []struct {
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
			Path string `json:"path"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &doc) // best-effort: a malformed body yields no items

	self := sink.Entity(graph.TypeDomain, in.Key, in.Key)
	seen := map[string]struct{}{}
	for _, it := range doc.Items {
		repo := strings.TrimSpace(it.Repository.FullName)
		if repo == "" || !strings.Contains(repo, "/") {
			continue
		}
		if _, dup := seen[repo]; dup {
			continue
		}
		seen[repo] = struct{}{}
		r := sink.Entity(graph.TypeRepository, "github.com/"+repo, repo)
		sink.Fact(r, "mentions", in.Key, 0.7)
		sink.Fact(self, "code_reference", repo, 0.7)
	}
	return nil
}
