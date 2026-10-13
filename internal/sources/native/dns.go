// Package native holds recon sources written in Go that talk to the network
// directly, rather than shelling out to an external tool.
package native

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// Resolver is the subset of *net.Resolver the DNS source needs, so the source can
// be tested with a fake instead of real DNS.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// DNS resolves a host to its addresses and CNAME. It emits an ip entity and a
// resolves_to edge for each address, a cname fact, and the CNAME target as a host
// so the engine resolves it in turn.
type DNS struct {
	Resolver Resolver
}

// NewDNS returns a DNS source using the system resolver.
func NewDNS() *DNS { return &DNS{Resolver: net.DefaultResolver} }

// Capability marks DNS as active: resolution queries live name servers, so it does
// not run in a passive-only run.
func (d *DNS) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/dns",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{graph.TypeIP, graph.TypeHost},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; the system resolver is always present.
func (d *DNS) Available(sources.Env) bool { return true }

// Collect resolves the input host.
func (d *DNS) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	host := in.Key
	self := sink.Entity(graph.TypeHost, host, host)

	addrs, err := d.Resolver.LookupHost(ctx, host)
	if err != nil && !notFound(err) {
		return err // a timeout or server failure: logged by the engine, not fatal
	}
	nxdomain := notFound(err)
	for _, a := range addrs {
		ip := sink.Entity(graph.TypeIP, a, a)
		sink.Edge(self, ip, graph.RelResolvesTo, 1.0)
	}

	// A CNAME is recorded as a fact and its target emitted as a host, so the target is
	// chased and a dangling CNAME is visible.
	if cname, cerr := d.Resolver.LookupCNAME(ctx, host); cerr == nil {
		cn := strings.TrimSuffix(strings.ToLower(cname), ".")
		if cn != "" && !strings.EqualFold(cn, host) {
			sink.Fact(self, "cname", cn, 1.0)
			sink.Entity(graph.TypeHost, cn, cn)
			// A CNAME whose chain does not resolve (NXDOMAIN with no address) is
			// dangling: the target may be registrable by an attacker, the basis of a
			// subdomain takeover.
			if nxdomain && len(addrs) == 0 {
				sink.Fact(self, "finding", "high dangling-cname", 0.7)
				sink.Fact(self, "exposure", "dangling_cname", 0.7)
			}
		}
	}
	return nil
}

// notFound reports whether a lookup error is just "no such host", which for recon
// is an ordinary empty result, not a failure.
func notFound(err error) bool {
	if d, ok := errors.AsType[*net.DNSError](err); ok {
		return d.IsNotFound
	}
	return false
}
