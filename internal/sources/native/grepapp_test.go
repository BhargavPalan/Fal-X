package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestGrepAppFindsRepositories(t *testing.T) {
	const body = `{"hits":{"hits":[
		{"repo":{"raw":"acme/webapp"},"path":{"raw":"config/prod.yml"}},
		{"repo":{"raw":"acme/webapp"},"path":{"raw":"README.md"}},
		{"repo":{"raw":"someone/infra"},"path":{"raw":"main.tf"}}
	]}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	g := &GrepApp{Client: srv.Client(), BaseURL: srv.URL}
	s := &recSink{}
	if err := g.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "acme.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeRepository, "github.com/acme/webapp") ||
		!s.hasEntity(graph.TypeRepository, "github.com/someone/infra") {
		t.Errorf("expected repository entities, entities=%+v", s.entities)
	}
	repos := 0
	for _, e := range s.entities {
		if e.t == graph.TypeRepository {
			repos++
		}
	}
	if repos != 2 { // acme/webapp appears twice but is one repository
		t.Errorf("expected 2 distinct repositories, got %d", repos)
	}
}
