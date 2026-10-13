package native

import (
	"context"
	"net"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

// fakeResolver answers from fixed maps, so the DNS source is tested without network.
type fakeResolver struct {
	hosts map[string][]string
	cname map[string]string
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := f.hosts[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{IsNotFound: true}
}

func (f fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := f.cname[host]; ok {
		return c, nil
	}
	return host, nil
}

// recSink records emissions for assertion.
type recSink struct {
	entities []struct {
		t   graph.EntityType
		key string
	}
	facts []struct{ key, value string }
	edges []graph.EdgeType
}

func (s *recSink) Entity(t graph.EntityType, key, _ string) graph.Ref {
	s.entities = append(s.entities, struct {
		t   graph.EntityType
		key string
	}{t, key})
	return graph.Ref(len(s.entities))
}
func (s *recSink) Fact(_ graph.Ref, key, value string, _ float64) {
	s.facts = append(s.facts, struct{ key, value string }{key, value})
}
func (s *recSink) Edge(_, _ graph.Ref, rel graph.EdgeType, _ float64) {
	s.edges = append(s.edges, rel)
}

func (s *recSink) hasEntity(t graph.EntityType, key string) bool {
	for _, e := range s.entities {
		if e.t == t && e.key == key {
			return true
		}
	}
	return false
}

func TestDNSResolvesAddresses(t *testing.T) {
	d := &DNS{Resolver: fakeResolver{
		hosts: map[string][]string{"www.example.com": {"192.0.2.1", "192.0.2.2"}},
	}}
	s := &recSink{}
	if err := d.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "www.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeIP, "192.0.2.1") || !s.hasEntity(graph.TypeIP, "192.0.2.2") {
		t.Errorf("expected both IPs as entities, got %+v", s.entities)
	}
	resolves := 0
	for _, r := range s.edges {
		if r == graph.RelResolvesTo {
			resolves++
		}
	}
	if resolves != 2 {
		t.Errorf("resolves_to edges = %d, want 2", resolves)
	}
}

func TestDNSRecordsCNAME(t *testing.T) {
	d := &DNS{Resolver: fakeResolver{
		hosts: map[string][]string{"shop.example.com": {"192.0.2.9"}},
		cname: map[string]string{"shop.example.com": "example.myshopify.com."},
	}}
	s := &recSink{}
	if err := d.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "shop.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	foundCNAME := false
	for _, f := range s.facts {
		if f.key == "cname" && f.value == "example.myshopify.com" {
			foundCNAME = true
		}
	}
	if !foundCNAME {
		t.Errorf("expected cname fact, got %+v", s.facts)
	}
	if !s.hasEntity(graph.TypeHost, "example.myshopify.com") {
		t.Errorf("expected CNAME target emitted as a host, got %+v", s.entities)
	}
}

func TestDNSDetectsDanglingCNAME(t *testing.T) {
	// The host has a CNAME but does not resolve (NXDOMAIN): a takeover candidate.
	d := &DNS{Resolver: fakeResolver{
		hosts: map[string][]string{}, // host resolves to nothing
		cname: map[string]string{"gone.example.com": "abandoned.herokuapp.com."},
	}}
	s := &recSink{}
	if err := d.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "gone.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	var gotFinding, gotExposure bool
	for _, f := range s.facts {
		if f.key == "finding" && f.value == "high dangling-cname" {
			gotFinding = true
		}
		if f.key == "exposure" && f.value == "dangling_cname" {
			gotExposure = true
		}
	}
	if !gotFinding || !gotExposure {
		t.Errorf("expected a dangling-cname finding+exposure, facts=%+v", s.facts)
	}
}

func TestDNSResolvingCNAMEIsNotDangling(t *testing.T) {
	// A CNAME that does resolve must not be flagged.
	d := &DNS{Resolver: fakeResolver{
		hosts: map[string][]string{"shop.example.com": {"192.0.2.9"}},
		cname: map[string]string{"shop.example.com": "shops.myshopify.com."},
	}}
	s := &recSink{}
	if err := d.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "shop.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	for _, f := range s.facts {
		if f.key == "finding" {
			t.Errorf("a resolving CNAME must not be flagged dangling, got %+v", f)
		}
	}
}

func TestDNSNoSuchHostIsNotError(t *testing.T) {
	d := &DNS{Resolver: fakeResolver{hosts: map[string][]string{}}}
	s := &recSink{}
	if err := d.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "nope.example.com"}, s); err != nil {
		t.Errorf("NXDOMAIN should not be an error, got %v", err)
	}
}
