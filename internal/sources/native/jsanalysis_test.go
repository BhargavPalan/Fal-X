package native

import (
	"context"
	"net/http"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestJSAnalysisExtractsEndpointsAndExposedSourceMap(t *testing.T) {
	const js = `
		var base = "/api/v1/users";
		function load(){ return fetch("/internal/config"); }
		//# sourceMappingURL=app.js.map
	`
	const mapJSON = `{"version":3,"sources":["webpack:///src/secret.js","webpack:///src/app.js"],"mappings":"AAAA"}`

	doer := doerFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case "https://cdn.example.com/app.js":
			return stubResp(200, js), nil
		case "https://cdn.example.com/app.js.map":
			return stubResp(200, mapJSON), nil
		default:
			return stubResp(404, ""), nil
		}
	})
	j := &JSAnalysis{Client: doer}
	s := &recSink{}
	if err := j.Collect(context.Background(), graph.Entity{Type: graph.TypeURL, Key: "https://cdn.example.com/app.js"}, s); err != nil {
		t.Fatal(err)
	}

	if !s.hasEntity(graph.TypeEndpoint, "/api/v1/users") || !s.hasEntity(graph.TypeEndpoint, "/internal/config") {
		t.Errorf("expected the JS endpoints to be extracted, got %+v", s.entities)
	}
	if !s.hasFact("finding", "medium exposed-sourcemap") || !s.hasFact("exposure", "exposed_sourcemap") {
		t.Errorf("expected an exposed-sourcemap finding, got %+v", s.facts)
	}
	if !s.hasEntity(graph.TypeDocument, "https://cdn.example.com/app.js.map") {
		t.Error("expected the source map to be recorded as a document")
	}
	if !s.hasFact("sourcemap_source", "webpack:///src/secret.js") {
		t.Errorf("expected the map's original sources to be kept as leads, got %+v", s.facts)
	}
}

func TestJSAnalysisDoesNotFollowOffHostSourceMap(t *testing.T) {
	// The sourceMappingURL points at a different host (a cloud metadata endpoint): the
	// SSRF guard must stop it being fetched, so no map document or finding is produced.
	const js = "var x=1;\n//# sourceMappingURL=http://169.254.169.254/latest/meta-data/app.js.map\n"
	doer := doerFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "169.254.169.254" {
			t.Fatalf("off-host source map must never be fetched: %s", r.URL)
		}
		if r.URL.String() == "https://cdn.example.com/app.js" {
			return stubResp(200, js), nil
		}
		return stubResp(404, ""), nil
	})
	j := &JSAnalysis{Client: doer}
	s := &recSink{}
	if err := j.Collect(context.Background(), graph.Entity{Type: graph.TypeURL, Key: "https://cdn.example.com/app.js"}, s); err != nil {
		t.Fatal(err)
	}
	if s.hasFact("finding", "medium exposed-sourcemap") || s.hasEntity(graph.TypeDocument, "http://169.254.169.254/latest/meta-data/app.js.map") {
		t.Errorf("an off-host source map must not be followed, got %+v / %+v", s.entities, s.facts)
	}
}

func TestJSAnalysisIgnoresNonJavaScript(t *testing.T) {
	doer := doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("a non-.js URL must not be fetched")
		return nil, nil
	})
	j := &JSAnalysis{Client: doer}
	s := &recSink{}
	if err := j.Collect(context.Background(), graph.Entity{Type: graph.TypeURL, Key: "https://cdn.example.com/index.html"}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.entities) != 0 {
		t.Errorf("a non-JS URL must emit nothing, got %+v", s.entities)
	}
}
