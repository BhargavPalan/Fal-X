package native

import (
	"context"
	"net"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// AddrResolver is the subset of *net.Resolver the reverse-DNS source needs.
type AddrResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// RevDNS looks up an IP's PTR records and emits each name as a host. A reverse record
// often names infrastructure no forward enumeration reached (a co-located service on
// a shared IP); the emitted host re-enters the engine and is resolved forward, which
// also confirms the PTR (forward-confirmed reverse DNS) when the host points back.
// It is active: it queries live name servers.
type RevDNS struct {
	Resolver AddrResolver
}

// NewRevDNS returns a reverse-DNS source using the system resolver.
func NewRevDNS() *RevDNS { return &RevDNS{Resolver: net.DefaultResolver} }

// Capability marks the source active, consuming an IP and producing hosts.
func (r *RevDNS) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/revdns",
		Consumes: []graph.EntityType{graph.TypeIP},
		Produces: []graph.EntityType{graph.TypeHost},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; the system resolver is always present.
func (r *RevDNS) Available(sources.Env) bool { return true }

// Collect reads the IP's PTR records. An IP with no reverse record is ordinary, not a
// failure.
func (r *RevDNS) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	names, err := r.Resolver.LookupAddr(ctx, in.Key)
	if err != nil && !notFound(err) {
		return err
	}
	self := sink.Entity(graph.TypeIP, in.Key, in.Key)
	for _, name := range names {
		h := trimName(name)
		if !isHostname(h) {
			continue
		}
		sink.Fact(self, "ptr", h, 0.9)
		sink.Entity(graph.TypeHost, h, h)
	}
	return nil
}
