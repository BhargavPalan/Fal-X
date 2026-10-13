package native

import (
	"context"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestPermuteEmitsCandidates(t *testing.T) {
	p := &Permute{Resolver: fakeResolver{}, Tokens: []string{"dev", "admin", "api"}}
	s := &recSink{}
	if err := p.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"dev.example.com", "admin.example.com", "api.example.com"} {
		if !s.hasEntity(graph.TypeHost, h) {
			t.Errorf("expected candidate %q, entities=%+v", h, s.entities)
		}
	}
}

func TestPermuteSkipsWildcardZone(t *testing.T) {
	// The wildcard probe resolves, so the zone is a wildcard and no candidates should
	// be generated.
	p := &Permute{
		Resolver: fakeResolver{hosts: map[string][]string{
			wildcardProbe + "example.com": {"192.0.2.1"},
		}},
		Tokens: []string{"dev", "admin"},
	}
	s := &recSink{}
	if err := p.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if s.hasEntity(graph.TypeHost, "dev.example.com") {
		t.Errorf("a wildcard zone should produce no candidates, entities=%+v", s.entities)
	}
	if !s.hasFact("wildcard", "true") {
		t.Errorf("expected a wildcard fact, facts=%+v", s.facts)
	}
}
