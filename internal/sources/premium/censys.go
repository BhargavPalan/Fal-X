package premium

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Censys reads Censys' host API: the services it has validated on an IP, their ports
// and software, and the certificates presented. Its key is an API id and secret joined
// by a colon ("id:secret"), sent as HTTP Basic auth. It is passive and key-gated.
type Censys struct {
	Client  Doer
	BaseURL string
}

// NewCensys returns a Censys adapter.
func NewCensys() *Censys {
	return &Censys{Client: &http.Client{Timeout: 20 * time.Second}, BaseURL: "https://search.censys.io"}
}

// Capability marks it passive and key-gated, consuming an IP.
func (c *Censys) Capability() sources.Capability {
	return sources.Capability{
		Name:      "premium/censys",
		Consumes:  []graph.EntityType{graph.TypeIP},
		Produces:  []graph.EntityType{graph.TypeService, graph.TypeCertificate},
		Passive:   true,
		NeedsAuth: true,
		CacheTTL:  24 * time.Hour,
		Cost:      1,
	}
}

// Available reports whether a Censys id:secret key is present.
func (c *Censys) Available(env sources.Env) bool {
	return strings.Contains(env.Keys["censys"], ":")
}

// Collect reads the IP's Censys host record.
func (c *Censys) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	key := keyFromContext(ctx, "censys")
	if !strings.Contains(key, ":") {
		return nil
	}
	if !bareIP(in.Key) {
		return nil
	}
	basic := base64.StdEncoding.EncodeToString([]byte(key))
	body := authGet(ctx, c.Client, strings.TrimRight(c.BaseURL, "/")+"/api/v2/hosts/"+in.Key,
		map[string]string{"Authorization": "Basic " + basic})
	if len(body) == 0 {
		return nil
	}
	var doc struct {
		Result struct {
			Services []struct {
				Port        int    `json:"port"`
				ServiceName string `json:"service_name"`
				Certificate string `json:"certificate"`
			} `json:"services"`
		} `json:"result"`
	}
	_ = json.Unmarshal(body, &doc) // best-effort: a malformed body yields no services

	self := sink.Entity(graph.TypeIP, in.Key, in.Key)
	for _, s := range doc.Result.Services {
		if s.Port <= 0 {
			continue
		}
		addr := net.JoinHostPort(in.Key, strconv.Itoa(s.Port))
		svc := sink.Entity(graph.TypeService, addr, addr)
		sink.Edge(self, svc, graph.RelHosts, 0.9)
		sink.Fact(svc, "port", strconv.Itoa(s.Port), 0.9)
		if s.ServiceName != "" {
			sink.Fact(svc, "service", strings.ToLower(s.ServiceName), 0.8)
		}
		if fp := strings.TrimSpace(s.Certificate); fp != "" {
			ce := sink.Entity(graph.TypeCertificate, strings.ToLower(fp), fp)
			sink.Edge(svc, ce, graph.RelPresentsCert, 0.8)
		}
	}
	return nil
}

// bareIP reports whether s parses as a plain IP address.
func bareIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}
