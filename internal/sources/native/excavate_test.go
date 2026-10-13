package native

import (
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestExcavateMinesHostsEmailsAndSecrets(t *testing.T) {
	s := &recSink{}
	self := s.Entity(graph.TypeHost, "www.example.com", "www.example.com")
	u := s.Entity(graph.TypeURL, "https://www.example.com/", "https://www.example.com/")
	body := []byte(`
		<a href="https://api.example.com/v1">api</a>
		<a href="https://cdn.othersite.net/x">external</a>
		contact: admin@example.com
		var k = "AKIAIOSFODNN7EXAMPLE";
	`)
	excavate(body, self, u, "www.example.com", s)

	if !s.hasEntity(graph.TypeHost, "api.example.com") {
		t.Errorf("expected same-estate host mined, entities=%+v", s.entities)
	}
	if s.hasEntity(graph.TypeHost, "cdn.othersite.net") {
		t.Errorf("an external host must not be mined, entities=%+v", s.entities)
	}
	if !s.hasEntity(graph.TypeEmail, "admin@example.com") {
		t.Errorf("expected mined email, entities=%+v", s.entities)
	}
	if !s.hasFact("finding", "high leaked-secret aws-access-key") {
		t.Errorf("expected a leaked-secret finding, facts=%+v", s.facts)
	}
	// The raw secret must never be stored anywhere.
	for _, f := range s.facts {
		if strings.Contains(f.value, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("raw secret leaked into a fact: %+v", f)
		}
	}
	for _, e := range s.entities {
		if strings.Contains(e.key, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("raw secret leaked into an entity key: %+v", e)
		}
	}
}

func TestExcavateMinesAnalyticsID(t *testing.T) {
	s := &recSink{}
	self := s.Entity(graph.TypeHost, "x.com", "x.com")
	u := s.Entity(graph.TypeURL, "https://x.com/", "https://x.com/")
	body := []byte(`<script>ga('create','UA-12345-6');gtag('config','G-ABC1234567');</script> GTM-ABCD12`)
	excavate(body, self, u, "x.com", s)
	for _, id := range []string{"UA-12345-6", "G-ABC1234567", "GTM-ABCD12"} {
		if !s.hasFact("analytics_id", id) {
			t.Errorf("expected analytics_id %q, facts=%+v", id, s.facts)
		}
	}
}

func TestRegisteredDomain(t *testing.T) {
	for in, want := range map[string]string{
		"api.example.com":   "example.com",
		"example.com":       "example.com",
		"a.b.c.example.com": "example.com",
		"localhost":         "",
	} {
		if got := registeredDomain(in); got != want {
			t.Errorf("registeredDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
