package native

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// ASN expands an IP into the routing infrastructure that announces it: the covering
// prefixes (netblocks), the autonomous systems that originate them, and the operator
// behind each. It reads the free, no-key BGPView API, so it is passive. The edges it
// builds (ip -> netblock -> asn) let correlation and the attack-path layer reason
// about shared hosting and blast radius.
type ASN struct {
	Client  Doer
	BaseURL string
}

// NewASN returns an ASN source using the BGPView API.
func NewASN() *ASN {
	return &ASN{Client: &http.Client{Timeout: 20 * time.Second}, BaseURL: "https://api.bgpview.io"}
}

// Capability marks the source passive, consuming an IP and producing netblocks and
// ASNs.
func (a *ASN) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/asn",
		Consumes: []graph.EntityType{graph.TypeIP},
		Produces: []graph.EntityType{graph.TypeNetblock, graph.TypeASN},
		Passive:  true,
		CacheTTL: 24 * time.Hour,
		Cost:     1,
	}
}

// Available is always true; BGPView needs no credentials.
func (a *ASN) Available(sources.Env) bool { return true }

// bgpViewIP is the subset of BGPView's /ip/{ip} response the source reads.
type bgpViewIP struct {
	Status string `json:"status"`
	Data   struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
			ASN    struct {
				ASN         int    `json:"asn"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"asn"`
		} `json:"prefixes"`
	} `json:"data"`
}

// Collect reads the IP's routing record. An IP BGPView does not know (an empty or 404
// result) is not an error.
func (a *ASN) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	// The IP key is netip-canonical upstream; re-checking it here rejects anything that
	// is not a bare address before it is interpolated into the request URL.
	if !bareIP(in.Key) {
		return nil
	}
	body, _ := getBody(ctx, a.Client, strings.TrimRight(a.BaseURL, "/")+"/ip/"+in.Key, 2)
	if len(body) == 0 {
		return nil
	}

	// Best-effort: a malformed or non-"ok" response leaves doc empty and emits nothing.
	var doc bgpViewIP
	_ = json.Unmarshal(body, &doc)
	if doc.Status != "ok" {
		return nil
	}

	self := sink.Entity(graph.TypeIP, in.Key, in.Key)
	seenNet := map[string]bool{}
	seenASN := map[int]bool{}
	for _, p := range doc.Data.Prefixes {
		if p.Prefix == "" || seenNet[p.Prefix] {
			continue
		}
		seenNet[p.Prefix] = true
		nb := sink.Entity(graph.TypeNetblock, p.Prefix, p.Prefix)
		sink.Edge(self, nb, graph.RelInNetblock, 1.0)
		if p.ASN.ASN <= 0 {
			continue
		}
		as := "AS" + strconv.Itoa(p.ASN.ASN)
		ae := sink.Entity(graph.TypeASN, as, firstNonEmpty(p.ASN.Name, as))
		sink.Edge(nb, ae, graph.RelAnnouncedBy, 1.0)
		if !seenASN[p.ASN.ASN] {
			seenASN[p.ASN.ASN] = true
			asnFacts(ae, p.ASN.Name, p.ASN.Description, p.ASN.CountryCode, sink)
		}
	}
	return nil
}

// asnFacts attaches the operator identity of an ASN.
func asnFacts(on graph.Ref, name, desc, country string, sink sources.Sink) {
	if name != "" {
		sink.Fact(on, "asn_name", name, 1.0)
	}
	if desc != "" {
		sink.Fact(on, "asn_org", desc, 0.9)
	}
	if country != "" {
		sink.Fact(on, "country", country, 0.8)
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// bareIP reports whether s parses as a plain IP address.
func bareIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}
