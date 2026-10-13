package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestCORSReflectionWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect whatever Origin was sent, and allow credentials: the worst case.
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	c := &CORS{Client: srv.Client()}
	s := &recSink{}
	if err := c.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: host}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasFact("finding", "high cors-origin-reflection-with-credentials") {
		t.Errorf("expected reflection+credentials finding, facts=%+v", s.facts)
	}
	if !s.hasFact("exposure", "cors_reflect_credentials") {
		t.Errorf("expected cors exposure class, facts=%+v", s.facts)
	}
}

func TestCORSSafeServerIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok")) // no CORS headers at all
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	c := &CORS{Client: srv.Client()}
	s := &recSink{}
	if err := c.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: host}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.facts) != 0 {
		t.Errorf("a server with no CORS headers must produce no findings, got %+v", s.facts)
	}
}
