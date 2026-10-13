package premium

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

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
func (s *recSink) Edge(_, _ graph.Ref, rel graph.EdgeType, _ float64) { s.edges = append(s.edges, rel) }

func (s *recSink) hasEntity(t graph.EntityType, key string) bool {
	for _, e := range s.entities {
		if e.t == t && e.key == key {
			return true
		}
	}
	return false
}
func (s *recSink) hasFact(key, value string) bool {
	for _, f := range s.facts {
		if f.key == key && f.value == value {
			return true
		}
	}
	return false
}

func TestShodanAvailableNeedsKey(t *testing.T) {
	s := NewShodan()
	if s.Available(sources.Env{}) {
		t.Error("Shodan should be unavailable without a key")
	}
	if !s.Available(sources.Env{Keys: map[string]string{"shodan": "k"}}) {
		t.Error("Shodan should be available with a key")
	}
}

func TestShodanParsesHost(t *testing.T) {
	const body = `{"org":"Example ISP","hostnames":["host.example.com"],"vulns":["CVE-2021-44228"],
		"data":[{"port":443,"product":"nginx","version":"1.18.0","cpe":["cpe:/a:nginx:nginx:1.18.0"]}]}`
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.URL.Query().Get("key")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	s := &Shodan{Client: srv.Client(), BaseURL: srv.URL}
	rec := &recSink{}
	ctx := sources.WithEnv(context.Background(), sources.Env{Keys: map[string]string{"shodan": "secret-key"}})
	if err := s.Collect(ctx, graph.Entity{Type: graph.TypeIP, Key: "192.0.2.1"}, rec); err != nil {
		t.Fatal(err)
	}
	if gotKey != "secret-key" {
		t.Errorf("key not sent: %q", gotKey)
	}
	if !rec.hasEntity(graph.TypeService, "192.0.2.1:443") || !rec.hasFact("tech", "nginx 1.18.0") {
		t.Errorf("service/version not parsed: entities=%+v facts=%+v", rec.entities, rec.facts)
	}
	if !rec.hasEntity(graph.TypeHost, "host.example.com") {
		t.Errorf("hostname not emitted: %+v", rec.entities)
	}
	if !rec.hasFact("finding", "unknown shodan CVE-2021-44228") {
		t.Errorf("vuln not emitted as finding: %+v", rec.facts)
	}
}

func TestShodanNoKeyIsSilent(t *testing.T) {
	s := NewShodan()
	rec := &recSink{}
	// No Env on the context: Collect must make no request and emit nothing.
	if err := s.Collect(context.Background(), graph.Entity{Type: graph.TypeIP, Key: "192.0.2.1"}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.entities) != 0 {
		t.Errorf("expected no emissions without a key, got %+v", rec.entities)
	}
}
