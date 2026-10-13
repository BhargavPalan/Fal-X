package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestPassiveSubsHackerTargetFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("www.example.com,192.0.2.1\napi.example.com,192.0.2.2\nunrelated.test,192.0.2.3\n"))
	}))
	defer srv.Close()

	p := &passiveSubs{
		name:   "passive/test",
		client: srv.Client(),
		build:  func(string) string { return srv.URL },
		parse:  parseHostComma,
	}
	s := &recSink{}
	if err := p.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeHost, "www.example.com") || !s.hasEntity(graph.TypeHost, "api.example.com") {
		t.Errorf("expected the two in-scope hosts, got %+v", s.entities)
	}
	if s.hasEntity(graph.TypeHost, "unrelated.test") {
		t.Error("out-of-scope host must be filtered")
	}
}

func TestParseOTX(t *testing.T) {
	body := []byte(`{"passive_dns":[{"hostname":"a.example.com"},{"hostname":"b.example.com"}]}`)
	got := parseOTX(body)
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Errorf("parseOTX = %v, want [a.example.com b.example.com]", got)
	}
}

func TestParseStringArray(t *testing.T) {
	got := parseStringArray([]byte(`["x.example.com","y.example.com"]`))
	if len(got) != 2 {
		t.Errorf("parseStringArray = %v, want 2 names", got)
	}
	if parseStringArray([]byte(`not json`)) != nil {
		t.Error("invalid JSON should parse to nil, not panic")
	}
}
