package native

import (
	"context"
	"net"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

type fakeAddr struct{ ptr map[string][]string }

func (f fakeAddr) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if n, ok := f.ptr[addr]; ok {
		return n, nil
	}
	return nil, &net.DNSError{IsNotFound: true}
}

func TestRevDNSEmitsPTRHosts(t *testing.T) {
	r := &RevDNS{Resolver: fakeAddr{ptr: map[string][]string{
		"192.0.2.10": {"mail.example.com.", "vpn.example.com."},
	}}}
	s := &recSink{}
	if err := r.Collect(context.Background(), graph.Entity{Type: graph.TypeIP, Key: "192.0.2.10"}, s); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"mail.example.com", "vpn.example.com"} {
		if !s.hasEntity(graph.TypeHost, h) {
			t.Errorf("expected PTR host %q, entities=%+v", h, s.entities)
		}
		if !s.hasFact("ptr", h) {
			t.Errorf("expected ptr fact %q, facts=%+v", h, s.facts)
		}
	}
}

func TestRevDNSNoRecordIsNotError(t *testing.T) {
	r := &RevDNS{Resolver: fakeAddr{}}
	s := &recSink{}
	if err := r.Collect(context.Background(), graph.Entity{Type: graph.TypeIP, Key: "192.0.2.99"}, s); err != nil {
		t.Errorf("an IP with no PTR should not error, got %v", err)
	}
}
