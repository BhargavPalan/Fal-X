package native

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// guidRe matches a tenant GUID in the OpenID issuer URL.
var guidRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// M365 maps a domain's Microsoft 365 / Entra ID footprint using only Microsoft's own
// unauthenticated endpoints: the user-realm service reveals whether the domain is a
// managed or federated M365 tenant and its federation brand, and the tenant's OpenID
// configuration yields the tenant GUID. This is the identity-perimeter context a recon
// of any M365-using organisation needs, and the target is never touched (the requests
// go to login.microsoftonline.com). It is passive and needs no key.
type M365 struct {
	Client  Doer
	BaseURL string
}

// NewM365 returns an M365 tenant source.
func NewM365() *M365 {
	return &M365{Client: &http.Client{Timeout: 15 * time.Second}, BaseURL: "https://login.microsoftonline.com"}
}

// Capability marks it passive, consuming a domain.
func (m *M365) Capability() sources.Capability {
	return sources.Capability{
		Name:     "passive/m365",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{},
		Passive:  true,
		CacheTTL: 24 * time.Hour,
		Cost:     1,
	}
}

// Available is always true; the endpoints need no credentials.
func (m *M365) Available(sources.Env) bool { return true }

// Collect reads the domain's M365 realm and tenant.
func (m *M365) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	base := strings.TrimRight(m.BaseURL, "/")
	self := sink.Entity(graph.TypeDomain, in.Key, in.Key)

	realm, _ := getBody(ctx, m.Client, base+"/getuserrealm.srf?login="+url.QueryEscape("info@"+in.Key)+"&json=1", 2)
	if len(realm) > 0 {
		var doc struct {
			NameSpaceType       string `json:"NameSpaceType"`
			FederationBrandName string `json:"FederationBrandName"`
			AuthURL             string `json:"AuthURL"`
		}
		_ = json.Unmarshal(realm, &doc)
		switch doc.NameSpaceType {
		case "Managed", "Federated":
			sink.Fact(self, "m365", strings.ToLower(doc.NameSpaceType), 0.9)
			if doc.FederationBrandName != "" {
				sink.Fact(self, "m365_brand", doc.FederationBrandName, 0.8)
			}
			// A federated realm's AuthURL names the external identity provider (ADFS,
			// Okta, Ping), a pivot into the SSO surface.
			if doc.AuthURL != "" {
				if h := authHost(doc.AuthURL); isHostname(h) {
					sink.Fact(self, "federation_idp", h, 0.8)
					sink.Entity(graph.TypeHost, h, h)
				}
			}
		}
	}

	config, _ := getBody(ctx, m.Client, base+"/"+url.PathEscape(in.Key)+"/v2.0/.well-known/openid-configuration", 2)
	if guid := guidRe.Find(config); guid != nil {
		sink.Fact(self, "azure_tenant_id", string(guid), 0.9)
	}
	return nil
}

// authHost extracts the host from a federation AuthURL.
func authHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return trimName(u.Hostname())
}
