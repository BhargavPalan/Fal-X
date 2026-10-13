package native

import (
	"context"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// URLParams lifts the query parameters out of a discovered URL into parameter entities,
// building the inventory of inputs an application accepts without sending a single
// request. It is passive: it reads the URL the graph already holds.
type URLParams struct{}

// NewURLParams returns the extractor.
func NewURLParams() *URLParams { return &URLParams{} }

// Capability marks it passive, consuming a URL and producing parameters.
func (URLParams) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/urlparams",
		Consumes: []graph.EntityType{graph.TypeURL},
		Produces: []graph.EntityType{graph.TypeParameter},
		Passive:  true,
		Cost:     1,
	}
}

// Available is always true.
func (URLParams) Available(sources.Env) bool { return true }

// Collect emits a parameter for each distinct query key on the URL.
func (URLParams) Collect(_ context.Context, in graph.Entity, sink sources.Sink) error {
	u, ok := parseWebURL(in.Key)
	if !ok {
		return nil
	}
	q := u.Query()
	if len(q) == 0 {
		return nil
	}
	self := sink.Entity(graph.TypeURL, in.Key, in.Key)
	for name := range q {
		if name == "" {
			continue
		}
		key := name + "@query"
		pe := sink.Entity(graph.TypeParameter, key, name)
		sink.Edge(self, pe, graph.RelHasParam, 1.0)
	}
	return nil
}
