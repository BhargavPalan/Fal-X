package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestWebSpecFindsGraphQLAndOpenAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/graphql" && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
		case r.URL.Path == "/swagger.json":
			_, _ = w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"x"},"paths":{"/users":{},"/admin":{}}}`))
		case r.URL.Path == "/":
			_, _ = w.Write([]byte("home"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	w := &WebSpec{Client: srv.Client()}
	s := &recSink{}
	if err := w.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: host}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasFact("finding", "medium graphql-introspection-enabled") {
		t.Errorf("expected graphql introspection finding, facts=%+v", s.facts)
	}
	if !s.hasFact("finding", "low exposed-api-spec") {
		t.Errorf("expected exposed-api-spec finding, facts=%+v", s.facts)
	}
	if !s.hasEntity(graph.TypeEndpoint, "/users") || !s.hasEntity(graph.TypeEndpoint, "/admin") {
		t.Errorf("expected spec paths as endpoints, entities=%+v", s.entities)
	}
}
