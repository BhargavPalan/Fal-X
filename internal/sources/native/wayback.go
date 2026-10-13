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

// maxWaybackURLs bounds how many archived URLs one domain contributes.
const maxWaybackURLs = 2000

// Wayback reads the Internet Archive's CDX index for every URL ever archived under a
// domain: old endpoints, forgotten parameters, and backup files that no longer appear
// in a live crawl but still describe the application. It is passive (it reads the
// archive, not the target) and needs no key.
type Wayback struct {
	Client  Doer
	BaseURL string
}

// NewWayback returns a Wayback source using the public CDX endpoint.
func NewWayback() *Wayback {
	return &Wayback{Client: &http.Client{Timeout: 30 * time.Second}, BaseURL: "http://web.archive.org"}
}

// Capability marks the source passive, consuming a domain and producing URLs and
// hosts.
func (wb *Wayback) Capability() sources.Capability {
	return sources.Capability{
		Name:     "passive/wayback",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeURL, graph.TypeHost},
		Passive:  true,
		CacheTTL: 12 * time.Hour,
		Cost:     1,
	}
}

// Available is always true; the archive needs no credentials.
func (wb *Wayback) Available(sources.Env) bool { return true }

// Collect reads the archived URLs for the domain and its subdomains.
func (wb *Wayback) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	q := url.Values{}
	q.Set("url", "*."+in.Key+"/*")
	q.Set("output", "json")
	q.Set("fl", "original")
	q.Set("collapse", "urlkey")
	q.Set("limit", "5000")
	body, _ := getBody(ctx, wb.Client, strings.TrimRight(wb.BaseURL, "/")+"/cdx/search/cdx?"+q.Encode(), 2)
	if len(body) == 0 {
		return nil
	}

	// The CDX endpoint returns a JSON array of rows; the first row is the column
	// header. A non-array body (an outage page) parses to no rows and emits nothing.
	var rows [][]string
	_ = json.Unmarshal(body, &rows)

	self := sink.Entity(graph.TypeDomain, in.Key, in.Key)
	added := 0
	seen := map[string]struct{}{}
	for i, row := range rows {
		if i == 0 || len(row) == 0 || added >= maxWaybackURLs {
			continue
		}
		raw := strings.TrimSpace(row[0])
		u, perr := url.Parse(raw)
		if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		if _, dup := seen[raw]; dup {
			continue
		}
		seen[raw] = struct{}{}
		sink.Entity(graph.TypeURL, raw, raw)
		added++
		host := trimName(u.Hostname())
		if host != "" && isHostname(host) && (host == in.Key || strings.HasSuffix(host, "."+in.Key)) {
			h := sink.Entity(graph.TypeHost, host, host)
			sink.Edge(h, self, graph.RelSubdomainOf, 0.8)
		}
	}
	return nil
}
