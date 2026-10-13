package native

import (
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestParseRobotsEmitsPathsAndSitemaps(t *testing.T) {
	s := &recSink{}
	self := s.Entity(graph.TypeHost, "example.com", "example.com")
	w := &WebSurface{}
	added := 0
	body := "User-agent: *\nDisallow: /admin/\nDisallow: /tmp/*\nAllow: /public\nSitemap: https://example.com/sitemap.xml\n"
	w.parseRobots(body, "example.com", self, s, &added)

	if !s.hasFact("robots_path", "/admin/") {
		t.Errorf("expected the disallowed path recorded, facts=%+v", s.facts)
	}
	if !s.hasEntity(graph.TypeURL, "https://example.com/admin/") {
		t.Errorf("expected a concrete disallowed path as a URL, entities=%+v", s.entities)
	}
	// A wildcard pattern is not a fetchable URL.
	if s.hasEntity(graph.TypeURL, "https://example.com/tmp/*") {
		t.Errorf("a wildcard robots path must not become a URL, entities=%+v", s.entities)
	}
	if !s.hasEntity(graph.TypeURL, "https://example.com/sitemap.xml") {
		t.Errorf("expected the declared sitemap as a URL, entities=%+v", s.entities)
	}
}

func TestParseSecurityTxtHarvestsContact(t *testing.T) {
	s := &recSink{}
	self := s.Entity(graph.TypeHost, "example.com", "example.com")
	w := &WebSurface{}
	w.parseSecurityTxt("Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n", self, s)

	if !s.hasFact("security_txt", "present") {
		t.Errorf("expected the security.txt presence fact, facts=%+v", s.facts)
	}
	if !s.hasEntity(graph.TypeEmail, "security@example.com") {
		t.Errorf("expected the contact email entity, entities=%+v", s.entities)
	}
	if !s.hasFact("security_contact", "security@example.com") {
		t.Errorf("expected the security_contact fact, facts=%+v", s.facts)
	}
}
