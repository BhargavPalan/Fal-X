package native

import (
	"context"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestURLParamsExtractsQueryKeys(t *testing.T) {
	s := &recSink{}
	err := URLParams{}.Collect(context.Background(),
		graph.Entity{Type: graph.TypeURL, Key: "https://example.com/search?q=1&page=2&q=3"}, s)
	if err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeParameter, "q@query") || !s.hasEntity(graph.TypeParameter, "page@query") {
		t.Errorf("expected q and page parameters, entities=%+v", s.entities)
	}
	params := 0
	for _, e := range s.entities {
		if e.t == graph.TypeParameter {
			params++
		}
	}
	if params != 2 { // q appears twice but is one parameter
		t.Errorf("expected 2 distinct parameters, got %d", params)
	}
}

func TestURLParamsNoQueryIsSilent(t *testing.T) {
	s := &recSink{}
	if err := (URLParams{}).Collect(context.Background(),
		graph.Entity{Type: graph.TypeURL, Key: "https://example.com/path"}, s); err != nil {
		t.Fatal(err)
	}
	for _, e := range s.entities {
		if e.t == graph.TypeParameter {
			t.Errorf("no parameters expected, got %+v", e)
		}
	}
}
