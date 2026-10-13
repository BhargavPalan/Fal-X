package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestHIBPEmitsBreaches(t *testing.T) {
	const body = `[{"Name":"Adobe","Title":"Adobe","BreachDate":"2013-10-04","PwnCount":152445165,"DataClasses":["Passwords","Usernames"]}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	h := &HIBP{Client: srv.Client(), BaseURL: srv.URL}
	s := &recSink{}
	if err := h.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "adobe.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeLeak, "hibp:Adobe") {
		t.Errorf("expected a leak entity, entities=%+v", s.entities)
	}
	if !s.hasFact("finding", "medium breach-exposure Adobe") || !s.hasFact("pwn_count", "152445165") {
		t.Errorf("expected breach finding + pwn count, facts=%+v", s.facts)
	}
}
