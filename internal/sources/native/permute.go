package native

import (
	"context"
	"net"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// HostResolver is the one lookup the permutation source needs.
type HostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// wildcardProbe is an unlikely label used to detect a wildcard zone: if it resolves,
// every candidate would too, so permutation is pointless and skipped.
const wildcardProbe = "falx-wildcard-probe-zzqq9."

// permuteTokens are the environment, role and service prefixes most likely to name a
// real but unlinked subdomain. Resolution (the DNS source) prunes the misses, so a
// generous list costs little.
var permuteTokens = []string{
	"dev", "develop", "staging", "stage", "test", "testing", "qa", "uat", "preprod",
	"prod", "demo", "sandbox", "beta", "alpha", "internal", "intranet", "corp",
	"api", "api-dev", "api-staging", "api-test", "admin", "portal", "dashboard",
	"app", "apps", "web", "internal-api", "gateway", "proxy", "edge",
	"vpn", "remote", "citrix", "rdp", "ssh", "bastion", "jump",
	"mail", "smtp", "webmail", "autodiscover", "owa", "exchange", "mx",
	"git", "gitlab", "bitbucket", "jenkins", "ci", "jira", "confluence", "wiki", "docs",
	"status", "monitor", "monitoring", "grafana", "kibana", "prometheus", "metrics",
	"db", "database", "mysql", "postgres", "redis", "mongo", "elastic", "backup",
	"old", "legacy", "new", "cdn", "static", "assets", "media", "files", "uploads",
	"store", "shop", "checkout", "payment", "billing", "account", "login", "auth",
	"sso", "oauth", "id", "secure", "registry", "docker", "k8s", "s3", "storage",
	"m", "mobile", "cpanel", "webmin", "phpmyadmin", "pma", "staging2", "dev2",
}

// Permute generates likely subdomains for a domain and emits each as a candidate
// host; the engine resolves them and keeps the ones that exist. It first probes for a
// wildcard zone, in which every name resolves, and skips generation there so it does
// not flood the graph with false hosts. It is active: the candidates it emits are only
// useful once resolution (an active source) runs.
type Permute struct {
	Resolver HostResolver
	Tokens   []string
}

// NewPermute returns a permutation source using the system resolver.
func NewPermute() *Permute { return &Permute{Resolver: net.DefaultResolver, Tokens: permuteTokens} }

// Capability marks the source active, consuming a domain and producing hosts.
func (p *Permute) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/permute",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeHost},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; it uses the system resolver.
func (p *Permute) Available(sources.Env) bool { return true }

// Collect emits a candidate host for each token, unless the zone is a wildcard.
func (p *Permute) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	domain := in.Key
	if addrs, _ := p.Resolver.LookupHost(ctx, wildcardProbe+domain); len(addrs) > 0 {
		// A wildcard zone: every candidate would resolve to the same place, so
		// generating them tells us nothing.
		sink.Fact(sink.Entity(graph.TypeDomain, domain, domain), "wildcard", "true", 0.9)
		return nil
	}
	self := sink.Entity(graph.TypeDomain, domain, domain)
	for _, tok := range p.Tokens {
		name := tok + "." + domain
		if !isHostname(name) {
			continue
		}
		h := sink.Entity(graph.TypeHost, name, name)
		sink.Edge(h, self, graph.RelSubdomainOf, 0.5) // a guess until resolution confirms it
	}
	return nil
}
