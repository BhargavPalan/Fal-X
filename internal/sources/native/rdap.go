package native

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// emailRe matches addresses well enough to harvest contacts from an RDAP response.
var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// RDAP reads a domain's registration record: its registration and expiry dates and
// any contact emails. It is passive (it queries the RDAP service, not the target)
// and needs no key.
type RDAP struct {
	Client  Doer
	BaseURL string
}

// NewRDAP returns an RDAP source using the rdap.org bootstrap, which redirects to
// the authoritative registry.
func NewRDAP() *RDAP {
	return &RDAP{Client: &http.Client{Timeout: 20 * time.Second}, BaseURL: "https://rdap.org"}
}

// Capability marks RDAP passive, consuming a domain.
func (r *RDAP) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/rdap",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeEmail},
		Passive:  true,
		CacheTTL: 24 * time.Hour,
		Cost:     1,
	}
}

// Available is always true; RDAP needs no credentials.
func (r *RDAP) Available(sources.Env) bool { return true }

// Collect fetches and parses the domain's RDAP record. A domain with no RDAP record
// is not an error.
func (r *RDAP) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	// Many domains lack an RDAP record (a 404), which is not a failure, so the error
	// is ignored and parsing proceeds only when a body came back.
	body, _ := getBody(ctx, r.Client, strings.TrimRight(r.BaseURL, "/")+"/domain/"+in.Key, 2)
	if len(body) == 0 {
		return nil
	}

	self := sink.Entity(graph.TypeDomain, in.Key, in.Key)

	var doc struct {
		Events []struct {
			EventAction string `json:"eventAction"`
			EventDate   string `json:"eventDate"`
		} `json:"events"`
	}
	// Best-effort: a malformed record still yields emails via the regex below.
	_ = json.Unmarshal(body, &doc)
	for _, e := range doc.Events {
		switch e.EventAction {
		case "registration":
			sink.Fact(self, "registered", e.EventDate, 1.0)
		case "expiration":
			sink.Fact(self, "expires", e.EventDate, 1.0)
		case "last changed":
			sink.Fact(self, "updated", e.EventDate, 0.9)
		}
	}

	for _, addr := range uniqueEmails(body) {
		sink.Entity(graph.TypeEmail, addr, addr)
		sink.Fact(self, "rdap_email", addr, 0.8)
	}
	return nil
}

// uniqueEmails extracts distinct lowercase addresses from a body, sorted for a
// deterministic order.
func uniqueEmails(body []byte) []string {
	seen := map[string]struct{}{}
	for _, m := range emailRe.FindAll(body, -1) {
		addr := strings.ToLower(string(m))
		seen[addr] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
