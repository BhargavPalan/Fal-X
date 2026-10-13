package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestWaybackEmitsArchivedURLs(t *testing.T) {
	// A CDX response: the first row is the column header, the rest are URLs.
	const body = `[["original"],
		["https://www.example.com/old?id=1"],
		["http://api.example.com/v1/users"],
		["https://evil.test/not-ours"]]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	wb := &Wayback{Client: srv.Client(), BaseURL: srv.URL}
	s := &recSink{}
	if err := wb.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"https://www.example.com/old?id=1", "http://api.example.com/v1/users"} {
		if !s.hasEntity(graph.TypeURL, u) {
			t.Errorf("expected archived URL %q, entities=%+v", u, s.entities)
		}
	}
	// A subdomain host is emitted for our domain...
	if !s.hasEntity(graph.TypeHost, "api.example.com") {
		t.Errorf("expected the archived host, entities=%+v", s.entities)
	}
	// ...but an unrelated host from a shared archive row is not.
	if s.hasEntity(graph.TypeHost, "evil.test") {
		t.Errorf("an out-of-domain host must not be emitted as our subdomain, entities=%+v", s.entities)
	}
}
