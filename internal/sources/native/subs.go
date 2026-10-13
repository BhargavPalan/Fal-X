package native

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// passiveSubs is a passive subdomain source: it queries one free, no-key provider
// that returns names for a domain. Several providers share this shape, differing
// only in the URL and how their response is parsed. Having more than one means a
// single provider being down (crt.sh often is) does not blind the scan.
type passiveSubs struct {
	name   string
	build  func(domain string) string
	parse  func(body []byte) []string
	client Doer
}

func (p *passiveSubs) Capability() sources.Capability {
	return sources.Capability{
		Name:     p.name,
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeHost},
		Passive:  true,
		CacheTTL: time.Hour,
		Cost:     1,
	}
}

func (p *passiveSubs) Available(sources.Env) bool { return true }

func (p *passiveSubs) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	body, err := getBody(ctx, p.client, p.build(in.Key), 2)
	if err != nil {
		return err
	}
	self := sink.Entity(graph.TypeDomain, in.Key, in.Key)
	seen := map[string]struct{}{}
	for _, raw := range p.parse(body) {
		name := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "*.")
		if !isHostname(name) {
			continue
		}
		if name != in.Key && !strings.HasSuffix(name, "."+in.Key) {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		h := sink.Entity(graph.TypeHost, name, name)
		sink.Edge(h, self, graph.RelSubdomainOf, 1.0)
	}
	return nil
}

func newClient() Doer { return &http.Client{Timeout: 20 * time.Second} }

// NewHackerTarget reads HackerTarget's free hostsearch (one "host,ip" per line).
func NewHackerTarget() sources.Source {
	return &passiveSubs{
		name:   "passive/hackertarget",
		client: newClient(),
		build:  func(d string) string { return "https://api.hackertarget.com/hostsearch/?q=" + d },
		parse:  parseHostComma,
	}
}

// NewOTX reads AlienVault OTX passive DNS.
func NewOTX() sources.Source {
	return &passiveSubs{
		name:   "passive/otx",
		client: newClient(),
		build: func(d string) string {
			return fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", d)
		},
		parse: parseOTX,
	}
}

// NewAnubis reads the Anubis subdomain database (a JSON array of names).
func NewAnubis() sources.Source {
	return &passiveSubs{
		name:   "passive/anubis",
		client: newClient(),
		build:  func(d string) string { return "https://jldc.me/anubis/subdomains/" + url.PathEscape(d) },
		parse:  parseStringArray,
	}
}

// NewSubdomainCenter reads subdomain.center (a JSON array of names).
func NewSubdomainCenter() sources.Source {
	return &passiveSubs{
		name:   "passive/subdomaincenter",
		client: newClient(),
		build:  func(d string) string { return "https://api.subdomain.center/?domain=" + url.QueryEscape(d) },
		parse:  parseStringArray,
	}
}

// NewCertSpotter reads certspotter's free issuances endpoint. Without a key it is
// rate-limited and returns recent issuances only, but it needs no credentials.
func NewCertSpotter() sources.Source {
	return &passiveSubs{
		name:   "passive/certspotter",
		client: newClient(),
		build: func(d string) string {
			return "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(d) +
				"&include_subdomains=true&expand=dns_names"
		},
		parse: parseCertSpotter,
	}
}

// NewRapidDNS reads rapiddns.io, which returns an HTML table of records; the host
// tokens are pulled out and the caller filters them to the queried domain.
func NewRapidDNS() sources.Source {
	return &passiveSubs{
		name:   "passive/rapiddns",
		client: newClient(),
		build:  func(d string) string { return "https://rapiddns.io/subdomain/" + url.PathEscape(d) + "?full=1" },
		parse:  parseHostTokens,
	}
}

// NewURLScan reads urlscan.io's search API, which lists the hosts seen in scans of a
// domain. It works without a key at a low rate limit.
func NewURLScan() sources.Source {
	return &passiveSubs{
		name:   "passive/urlscan",
		client: newClient(),
		build:  func(d string) string { return "https://urlscan.io/api/v1/search/?q=domain:" + url.QueryEscape(d) },
		parse:  parseURLScan,
	}
}

// parseHostComma reads "host,ip" lines, keeping the host. HackerTarget returns an
// error sentence on failure, which fails isHostname and is dropped by the caller.
func parseHostComma(body []byte) []string {
	var out []string
	for line := range strings.SplitSeq(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.IndexByte(line, ','); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return out
}

// parseStringArray reads a JSON array of hostnames.
func parseStringArray(body []byte) []string {
	var names []string
	if err := json.Unmarshal(body, &names); err != nil {
		return nil
	}
	return names
}

// parseOTX reads OTX passive-DNS hostnames.
func parseOTX(body []byte) []string {
	var doc struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	out := make([]string, 0, len(doc.PassiveDNS))
	for _, r := range doc.PassiveDNS {
		out = append(out, r.Hostname)
	}
	return out
}

// parseURLScan reads the result hostnames from a urlscan.io search response.
func parseURLScan(body []byte) []string {
	var doc struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	out := make([]string, 0, len(doc.Results))
	for _, r := range doc.Results {
		if r.Page.Domain != "" {
			out = append(out, r.Page.Domain)
		}
	}
	return out
}

// parseCertSpotter reads the dns_names of each certspotter issuance.
func parseCertSpotter(body []byte) []string {
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.DNSNames...)
	}
	return out
}

// hostTokenRe matches dotted hostname-shaped tokens, for pulling names out of an HTML
// response. The caller filters the tokens to the queried domain and revalidates each
// with isHostname, so an over-broad match here is harmless.
var hostTokenRe = regexp.MustCompile(`[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}))+`)

// parseHostTokens extracts hostname-shaped tokens from an arbitrary (HTML) body.
func parseHostTokens(body []byte) []string {
	return hostTokenRe.FindAllString(string(body), -1)
}
