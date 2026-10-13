package native

import (
	"context"
	"net"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// CNAMEResolver is the one lookup the CDN check needs.
type CNAMEResolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// CDNCheck classifies a host by the provider its CNAME points at: a CDN, a WAF, or a
// cloud/SaaS platform. The verdict tells the rest of the engine to treat the host's
// edge as the provider's, not the origin's (a port scan of a CDN address scans the
// CDN, not the target), and a CNAME to an unclaimed provider target is the signal a
// later takeover check looks for. It is active: it resolves the CNAME.
type CDNCheck struct {
	Resolver CNAMEResolver
}

// NewCDNCheck returns a CDN check using the system resolver.
func NewCDNCheck() *CDNCheck { return &CDNCheck{Resolver: net.DefaultResolver} }

// Capability marks the source active, consuming a host.
func (c *CDNCheck) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/cdncheck",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; it uses the system resolver.
func (c *CDNCheck) Available(sources.Env) bool { return true }

// Collect resolves the host's CNAME and, when it points at a known provider, records
// the verdict. A host with no CNAME, or one that matches no provider, is ordinary.
func (c *CDNCheck) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	// LookupCNAME errors when the host has no CNAME, which is ordinary; the empty-target
	// check below handles both that and a self-referential answer.
	cname, _ := c.Resolver.LookupCNAME(ctx, in.Key)
	target := trimName(cname)
	if target == "" || strings.EqualFold(target, in.Key) {
		return nil
	}
	provider, category := classifyCDN(target)
	if provider == "" {
		return nil
	}
	self := sink.Entity(graph.TypeHost, in.Key, in.Key)
	sink.Fact(self, category, provider, 0.9)
	sink.Fact(self, "cname_target", target, 0.9)
	return nil
}

// cdnRule maps a CNAME suffix to the provider it belongs to and the kind of service
// it is: cdn, waf, or cloud (a cloud/SaaS platform).
type cdnRule struct {
	suffix   string
	provider string
	category string
}

// cdnRules are matched by CNAME suffix, longest and most specific first within a
// provider. The list favours the providers a dangling CNAME most often points at.
var cdnRules = []cdnRule{
	{"cloudflare.net", "Cloudflare", "cdn"},
	{"cloudflare.com", "Cloudflare", "cdn"},
	{"edgekey.net", "Akamai", "cdn"},
	{"edgesuite.net", "Akamai", "cdn"},
	{"akamaiedge.net", "Akamai", "cdn"},
	{"akamaihd.net", "Akamai", "cdn"},
	{"akamai.net", "Akamai", "cdn"},
	{"fastly.net", "Fastly", "cdn"},
	{"fastlylb.net", "Fastly", "cdn"},
	{"cloudfront.net", "Amazon CloudFront", "cdn"},
	{"azureedge.net", "Azure CDN", "cdn"},
	{"azurefd.net", "Azure Front Door", "cdn"},
	{"trafficmanager.net", "Azure Traffic Manager", "cloud"},
	{"edgecastcdn.net", "Edgecast", "cdn"},
	{"netlify.app", "Netlify", "cloud"},
	{"netlifyglobalcdn.com", "Netlify", "cdn"},
	{"vercel-dns.com", "Vercel", "cloud"},
	{"vercel.app", "Vercel", "cloud"},
	{"incapdns.net", "Imperva Incapsula", "waf"},
	{"sucuri.net", "Sucuri", "waf"},
	{"impervadns.net", "Imperva", "waf"},
	{"herokudns.com", "Heroku", "cloud"},
	{"herokuapp.com", "Heroku", "cloud"},
	{"herokussl.com", "Heroku", "cloud"},
	{"github.io", "GitHub Pages", "cloud"},
	{"githubusercontent.com", "GitHub", "cloud"},
	{"myshopify.com", "Shopify", "cloud"},
	{"wpengine.com", "WP Engine", "cloud"},
	{"zendesk.com", "Zendesk", "cloud"},
	{"desk.com", "Desk", "cloud"},
	{"statuspage.io", "Statuspage", "cloud"},
	{"ghost.io", "Ghost", "cloud"},
	{"surge.sh", "Surge", "cloud"},
	{"bitbucket.io", "Bitbucket", "cloud"},
	{"readthedocs.io", "Read the Docs", "cloud"},
	{"fastly-edge.com", "Fastly", "cdn"},
	{"s3.amazonaws.com", "Amazon S3", "cloud"},
	{"s3-website", "Amazon S3", "cloud"},
	{"googleusercontent.com", "Google Cloud", "cloud"},
	{"appspot.com", "Google App Engine", "cloud"},
	{"azurewebsites.net", "Azure App Service", "cloud"},
	{"cloudapp.net", "Azure", "cloud"},
	{"cloudapp.azure.com", "Azure", "cloud"},
	{"elasticbeanstalk.com", "AWS Elastic Beanstalk", "cloud"},
	{"amazonaws.com", "AWS", "cloud"},
}

// classifyCDN returns the provider and category a CNAME target belongs to, or empty
// strings when none match.
func classifyCDN(target string) (provider, category string) {
	for _, r := range cdnRules {
		if target == r.suffix || strings.HasSuffix(target, "."+r.suffix) || strings.Contains(target, r.suffix) {
			return r.provider, r.category
		}
	}
	return "", ""
}
