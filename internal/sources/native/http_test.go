package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestHTTPProbeRecordsServerAndTitle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache/2.4.7 (Ubuntu)")
		_, _ = w.Write([]byte("<html><head><title>  Example  Home </title></head></html>"))
	}))
	defer srv.Close()

	p := &HTTPProbe{Client: srv.Client()}
	s := &recSink{}
	self := s.Entity(graph.TypeHost, "example.com", "example.com")
	if ok := p.emit(context.Background(), srv.URL, "example.com", self, s); !ok {
		t.Fatal("probe should have succeeded against the test server")
	}

	var gotServer, gotTitle, gotStatus bool
	for _, f := range s.facts {
		switch {
		case f.key == "server" && f.value == "Apache/2.4.7 (Ubuntu)":
			gotServer = true
		case f.key == "title" && f.value == "Example Home": // whitespace collapsed
			gotTitle = true
		case f.key == "status" && f.value == "200":
			gotStatus = true
		}
	}
	if !gotServer {
		t.Errorf("expected server fact, got %+v", s.facts)
	}
	if !gotTitle {
		t.Errorf("expected collapsed title fact, got %+v", s.facts)
	}
	if !gotStatus {
		t.Errorf("expected status fact, got %+v", s.facts)
	}
	if !s.hasEntity(graph.TypeURL, srv.URL) {
		t.Errorf("expected a url entity, got %+v", s.entities)
	}
}

func TestHTTPProbeRecordsTechAndSecurityHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		//nolint:gosec // fixture: a deliberately plain cookie whose value must not be stored
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "secret-session-token"})
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	p := &HTTPProbe{Client: srv.Client()}
	s := &recSink{}
	self := s.Entity(graph.TypeHost, "example.com", "example.com")
	if ok := p.emit(context.Background(), srv.URL, "example.com", self, s); !ok {
		t.Fatal("probe should have succeeded")
	}

	if !s.hasFact("tech", "PHP/8.1.2") {
		t.Errorf("expected X-Powered-By recorded as tech evidence, facts=%+v", s.facts)
	}
	if !s.hasFact("tech", "PHP") {
		t.Errorf("expected the PHPSESSID cookie mapped to PHP, facts=%+v", s.facts)
	}
	if !s.hasFact("sec_header", "Strict-Transport-Security") {
		t.Errorf("expected the HSTS header recorded as posture, facts=%+v", s.facts)
	}
	if !s.hasFact("content_type", "text/html; charset=utf-8") {
		t.Errorf("expected content_type fact, facts=%+v", s.facts)
	}
	// A cookie value may be a session secret and must never be stored.
	for _, f := range s.facts {
		if strings.Contains(f.value, "secret-session-token") {
			t.Errorf("cookie value leaked into a fact: %+v", f)
		}
	}
}

func TestHTTPProbeUnreachableIsNotError(t *testing.T) {
	p := NewHTTPProbe()
	s := &recSink{}
	// Nothing listens here; Collect must return nil (a source failure is not fatal).
	if err := p.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "127.0.0.1:1"}, s); err != nil {
		t.Errorf("unreachable host should not be an error, got %v", err)
	}
}
