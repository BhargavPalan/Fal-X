package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestInternetDBMinesPortsHostsVulns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"ip":"1.1.1.1",
			"ports":[80,443],
			"cpes":["cpe:/a:nginx:nginx:1.18.0"],
			"hostnames":["one.example.com"],
			"vulns":["CVE-2021-23017"],
			"tags":["cdn"]
		}`))
	}))
	defer srv.Close()

	s := &InternetDB{Client: srv.Client(), BaseURL: srv.URL}
	rs := &recSink{}
	if err := s.Collect(context.Background(), graph.Entity{Type: graph.TypeIP, Key: "1.1.1.1"}, rs); err != nil {
		t.Fatal(err)
	}

	if !rs.hasEntity(graph.TypeService, "1.1.1.1:80") || !rs.hasEntity(graph.TypeService, "1.1.1.1:443") {
		t.Errorf("expected service entities for ports 80 and 443, got %+v", rs.entities)
	}
	if !rs.hasEntity(graph.TypeHost, "one.example.com") {
		t.Errorf("expected hostname entity, got %+v", rs.entities)
	}
	var cpe, vuln bool
	for _, f := range rs.facts {
		if f.key == "cpe" && f.value == "cpe:/a:nginx:nginx:1.18.0" {
			cpe = true
		}
		if f.key == "shodan_vuln" && f.value == "CVE-2021-23017" {
			vuln = true
		}
	}
	if !cpe {
		t.Errorf("expected cpe fact, got %+v", rs.facts)
	}
	if !vuln {
		t.Errorf("expected shodan_vuln fact, got %+v", rs.facts)
	}
}
