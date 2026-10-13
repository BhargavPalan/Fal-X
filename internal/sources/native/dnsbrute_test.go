package native

import (
	"context"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestDNSBruteResolvesWords(t *testing.T) {
	b := &DNSBrute{
		Resolver: fakeResolver{hosts: map[string][]string{
			"admin.example.com": {"192.0.2.5"},
		}},
		Words: []string{"admin", "nope"},
		Conc:  4,
	}
	s := &recSink{}
	if err := b.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeHost, "admin.example.com") || !s.hasEntity(graph.TypeIP, "192.0.2.5") {
		t.Errorf("expected admin host + ip, entities=%+v", s.entities)
	}
	if s.hasEntity(graph.TypeHost, "nope.example.com") {
		t.Errorf("a non-resolving word must not be emitted, entities=%+v", s.entities)
	}
}

func TestDNSBruteFiltersWildcard(t *testing.T) {
	const wild = "10.0.0.1"
	b := &DNSBrute{
		Resolver: fakeResolver{hosts: map[string][]string{
			"falx-wild-a7f3b1.example.com": {wild},
			"falx-wild-9c2e8d.example.com": {wild},
			"falx-wild-4b6f0a.example.com": {wild},
			"admin.example.com":            {wild},        // only the wildcard address -> filtered
			"real.example.com":             {"192.0.2.9"}, // a distinct address -> kept
		}},
		Words: []string{"admin", "real"},
		Conc:  4,
	}
	s := &recSink{}
	if err := b.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeHost, "real.example.com") {
		t.Errorf("a host with a distinct address should be kept, entities=%+v", s.entities)
	}
	if s.hasEntity(graph.TypeHost, "admin.example.com") {
		t.Errorf("a host resolving only to the wildcard address must be filtered, entities=%+v", s.entities)
	}
}
