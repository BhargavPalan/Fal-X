package native

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// InternetDB reads Shodan's free, no-key InternetDB for an IP: the open ports,
// detected CPEs, associated hostnames and known CVEs Shodan already observed,
// without the scan touching the target. It is passive.
type InternetDB struct {
	Client  Doer
	BaseURL string
}

// NewInternetDB returns an InternetDB source.
func NewInternetDB() *InternetDB {
	return &InternetDB{Client: &http.Client{Timeout: 20 * time.Second}, BaseURL: "https://internetdb.shodan.io"}
}

// Capability marks it passive, consuming an IP.
func (s *InternetDB) Capability() sources.Capability {
	return sources.Capability{
		Name:     "passive/internetdb",
		Consumes: []graph.EntityType{graph.TypeIP},
		Produces: []graph.EntityType{graph.TypeService, graph.TypeHost},
		Passive:  true,
		CacheTTL: 24 * time.Hour,
		Cost:     1,
	}
}

// Available is always true; InternetDB needs no credentials.
func (s *InternetDB) Available(sources.Env) bool { return true }

// Collect reads the IP's InternetDB record. An IP with no record (404) is not an
// error.
func (s *InternetDB) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	body, _ := getBody(ctx, s.Client, strings.TrimRight(s.BaseURL, "/")+"/"+in.Key, 2)
	if len(body) == 0 {
		return nil
	}
	var doc struct {
		Ports     []int    `json:"ports"`
		CPEs      []string `json:"cpes"`
		Hostnames []string `json:"hostnames"`
		Vulns     []string `json:"vulns"`
		Tags      []string `json:"tags"`
	}
	// Best-effort: a malformed body leaves doc empty and the loops below emit nothing.
	_ = json.Unmarshal(body, &doc)

	self := sink.Entity(graph.TypeIP, in.Key, in.Key)
	for _, port := range doc.Ports {
		addr := net.JoinHostPort(in.Key, strconv.Itoa(port))
		svc := sink.Entity(graph.TypeService, addr, addr)
		sink.Edge(self, svc, graph.RelHosts, 0.9)
		sink.Fact(svc, "port", strconv.Itoa(port), 0.9)
	}
	for _, name := range doc.Hostnames {
		name = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*.")
		if !isHostname(name) {
			continue
		}
		h := sink.Entity(graph.TypeHost, name, name)
		sink.Edge(h, self, graph.RelResolvesTo, 0.8)
	}
	for _, cpe := range doc.CPEs {
		sink.Fact(self, "cpe", cpe, 0.8)
	}
	for _, v := range doc.Vulns {
		sink.Fact(self, "shodan_vuln", v, 0.7)
		// A CVE Shodan already attributes to this IP is a finding, so prioritize and
		// report surface it; intelligence enrichment supplies the weight.
		if strings.HasPrefix(v, "CVE-") {
			sink.Fact(self, "finding", "unknown internetdb "+v, 0.7)
		}
	}
	for _, tag := range doc.Tags {
		sink.Fact(self, "tag", tag, 0.7)
	}
	return nil
}
