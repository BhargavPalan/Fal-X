package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestCTDiscoversSubdomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Two rows, one with a newline-joined SAN list, a wildcard, a duplicate, and
		// an unrelated name that must be filtered out.
		_, _ = w.Write([]byte(`[
			{"name_value": "www.example.com\n*.example.com"},
			{"name_value": "api.example.com"},
			{"name_value": "www.example.com"},
			{"name_value": "unrelated.test"}
		]`))
	}))
	defer srv.Close()

	c := &CT{Client: srv.Client(), BaseURL: srv.URL}
	s := &recSink{}
	if err := c.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"www.example.com", "api.example.com", "example.com"} {
		if !s.hasEntity(graph.TypeHost, want) {
			t.Errorf("expected host %s, got %+v", want, s.entities)
		}
	}
	if s.hasEntity(graph.TypeHost, "unrelated.test") {
		t.Error("unrelated.test is outside the queried domain and must be filtered")
	}
	// www appears three times (list, duplicate row) but must be emitted once.
	n := 0
	for _, e := range s.entities {
		if e.t == graph.TypeHost && e.key == "www.example.com" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("www.example.com emitted %d times, want 1", n)
	}
}

func TestIsHostname(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want bool
	}{
		{"example.com", true},
		{"a.b.example.com", true},
		{"no-dot", false},
		{"bad_underscore.com", false},
		{"", false},
	} {
		if got := isHostname(tc.s); got != tc.want {
			t.Errorf("isHostname(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}
