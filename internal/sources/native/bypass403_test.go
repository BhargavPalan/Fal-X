package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestBypass403TrailingSlash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
		case "/admin/": // the proxy forbids /admin but the backend serves /admin/
			_, _ = w.Write([]byte("admin panel"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	b := &Bypass403{Client: srv.Client()}
	s := &recSink{}
	if err := b.Collect(context.Background(), graph.Entity{Type: graph.TypeURL, Key: srv.URL + "/admin"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasFact("finding", "high access-control-bypass trailing-slash") {
		t.Errorf("expected a bypass finding, facts=%+v", s.facts)
	}
}

func TestBypass403NonForbiddenIsSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok")) // everything is 200, nothing is forbidden
	}))
	defer srv.Close()

	b := &Bypass403{Client: srv.Client()}
	s := &recSink{}
	if err := b.Collect(context.Background(), graph.Entity{Type: graph.TypeURL, Key: srv.URL + "/admin"}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.facts) != 0 {
		t.Errorf("a non-forbidden URL must produce no findings, got %+v", s.facts)
	}
}
