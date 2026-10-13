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

// keyedSubs is the shared shape of the paid subdomain engines: a domain query against
// one provider that returns names, differing only in the key name, the auth header, the
// URL, and how the response is parsed.
type keyedSubs struct {
	name    string
	keyName string
	header  func(key string) map[string]string
	build   func(baseURL, domain string) string
	parse   func(body []byte) []string
	client  Doer
	baseURL string
}

func (k *keyedSubs) Capability() sources.Capability {
	return sources.Capability{
		Name:      k.name,
		Consumes:  []graph.EntityType{graph.TypeDomain},
		Produces:  []graph.EntityType{graph.TypeHost},
		Passive:   true,
		NeedsAuth: true,
		CacheTTL:  24 * time.Hour,
		Cost:      1,
	}
}

func (k *keyedSubs) Available(env sources.Env) bool { return env.Keys[k.keyName] != "" }

func (k *keyedSubs) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	key := keyFromContext(ctx, k.keyName)
	if key == "" {
		return nil
	}
	body := authGet(ctx, k.client, k.build(k.baseURL, in.Key), k.header(key))
	if len(body) == 0 {
		return nil
	}
	for _, name := range k.parse(body) {
		emitSub(sink, in.Key, name)
	}
	return nil
}

func newClient() Doer { return &http.Client{Timeout: 20 * time.Second} }

// NewSecurityTrails reads SecurityTrails' subdomain inventory (returns bare labels).
func NewSecurityTrails() sources.Source {
	return &keyedSubs{
		name: "premium/securitytrails", keyName: "securitytrails", client: newClient(),
		baseURL: "https://api.securitytrails.com",
		header:  func(key string) map[string]string { return map[string]string{"APIKEY": key} },
		build: func(base, d string) string {
			return strings.TrimRight(base, "/") + "/v1/domain/" + url.PathEscape(d) + "/subdomains"
		},
		parse: parseLabelList,
	}
}

// NewVirusTotal reads VirusTotal's observed subdomains (returns FQDNs).
func NewVirusTotal() sources.Source {
	return &keyedSubs{
		name: "premium/virustotal", keyName: "virustotal", client: newClient(),
		baseURL: "https://www.virustotal.com",
		header:  func(key string) map[string]string { return map[string]string{"x-apikey": key} },
		build: func(base, d string) string {
			return strings.TrimRight(base, "/") + "/api/v3/domains/" + url.PathEscape(d) + "/subdomains?limit=1000"
		},
		parse: parseVTData,
	}
}

// NewChaos reads ProjectDiscovery's Chaos subdomain dataset (returns bare labels).
func NewChaos() sources.Source {
	return &keyedSubs{
		name: "premium/chaos", keyName: "chaos", client: newClient(),
		baseURL: "https://dns.projectdiscovery.io",
		header:  func(key string) map[string]string { return map[string]string{"Authorization": key} },
		build: func(base, d string) string {
			return strings.TrimRight(base, "/") + "/dns/" + url.PathEscape(d) + "/subdomains"
		},
		parse: parseLabelList,
	}
}

// NewFullHunt reads FullHunt's attack-surface subdomain inventory (returns FQDNs).
func NewFullHunt() sources.Source {
	return &keyedSubs{
		name: "premium/fullhunt", keyName: "fullhunt", client: newClient(),
		baseURL: "https://fullhunt.io",
		header:  func(key string) map[string]string { return map[string]string{"X-API-KEY": key} },
		build: func(base, d string) string {
			return strings.TrimRight(base, "/") + "/api/v1/domain/" + url.PathEscape(d) + "/subdomains"
		},
		parse: parseHostsField,
	}
}

// NewLeakIX reads LeakIX's subdomain dataset (array of {subdomain}).
func NewLeakIX() sources.Source {
	return &keyedSubs{
		name: "premium/leakix", keyName: "leakix", client: newClient(),
		baseURL: "https://leakix.net",
		header: func(key string) map[string]string {
			return map[string]string{"api-key": key, "Accept": "application/json"}
		},
		build: func(base, d string) string {
			return strings.TrimRight(base, "/") + "/api/subdomains/" + url.PathEscape(d)
		},
		parse: parseLeakIX,
	}
}

// NewNetlas reads Netlas' domain search (items[].data.domain).
func NewNetlas() sources.Source {
	return &keyedSubs{
		name: "premium/netlas", keyName: "netlas", client: newClient(),
		baseURL: "https://app.netlas.io",
		header:  func(key string) map[string]string { return map[string]string{"X-API-Key": key} },
		build: func(base, d string) string {
			return strings.TrimRight(base, "/") + "/api/domains/?q=" + url.QueryEscape("*."+d) + "&fields=domain"
		},
		parse: parseNetlas,
	}
}

// NewZoomEye reads ZoomEye's domain search (list[].name).
func NewZoomEye() sources.Source {
	return &keyedSubs{
		name: "premium/zoomeye", keyName: "zoomeye", client: newClient(),
		baseURL: "https://api.zoomeye.org",
		header:  func(key string) map[string]string { return map[string]string{"API-KEY": key} },
		build: func(base, d string) string {
			return strings.TrimRight(base, "/") + "/domain/search?type=1&q=" + url.QueryEscape(d)
		},
		parse: parseZoomEye,
	}
}

// parseLeakIX reads a [{"subdomain":"www.example.com"}] response.
func parseLeakIX(body []byte) []string {
	var rows []struct {
		Subdomain string `json:"subdomain"`
	}
	if json.Unmarshal(body, &rows) != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Subdomain)
	}
	return out
}

// parseNetlas reads a {"items":[{"data":{"domain":"www.example.com"}}]} response.
func parseNetlas(body []byte) []string {
	var doc struct {
		Items []struct {
			Data struct {
				Domain string `json:"domain"`
			} `json:"data"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	out := make([]string, 0, len(doc.Items))
	for _, it := range doc.Items {
		out = append(out, it.Data.Domain)
	}
	return out
}

// parseZoomEye reads a {"list":[{"name":"www.example.com"}]} response.
func parseZoomEye(body []byte) []string {
	var doc struct {
		List []struct {
			Name string `json:"name"`
		} `json:"list"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	out := make([]string, 0, len(doc.List))
	for _, it := range doc.List {
		out = append(out, it.Name)
	}
	return out
}

// parseHostsField reads a {"hosts":["a.example.com"]} response.
func parseHostsField(body []byte) []string {
	var doc struct {
		Hosts []string `json:"hosts"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	return doc.Hosts
}

// parseLabelList reads a {"subdomains":["www","mail"]} response.
func parseLabelList(body []byte) []string {
	var doc struct {
		Subdomains []string `json:"subdomains"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	return doc.Subdomains
}

// parseVTData reads VirusTotal's {"data":[{"id":"sub.example.com"}]} response.
func parseVTData(body []byte) []string {
	var doc struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	out := make([]string, 0, len(doc.Data))
	for _, d := range doc.Data {
		out = append(out, d.ID)
	}
	return out
}
