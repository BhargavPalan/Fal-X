package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestASNExpandsRouting(t *testing.T) {
	const body = `{"status":"ok","data":{"prefixes":[
		{"prefix":"192.0.2.0/24","asn":{"asn":64512,"name":"EXAMPLE-AS","description":"Example Networks LLC","country_code":"US"}}
	]}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ip/192.0.2.1" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	a := &ASN{Client: srv.Client(), BaseURL: srv.URL}
	s := &recSink{}
	if err := a.Collect(context.Background(), graph.Entity{Type: graph.TypeIP, Key: "192.0.2.1"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeNetblock, "192.0.2.0/24") {
		t.Errorf("expected netblock entity, entities=%+v", s.entities)
	}
	if !s.hasEntity(graph.TypeASN, "AS64512") {
		t.Errorf("expected asn entity, entities=%+v", s.entities)
	}
	if !s.hasFact("asn_name", "EXAMPLE-AS") || !s.hasFact("asn_org", "Example Networks LLC") {
		t.Errorf("expected asn operator facts, facts=%+v", s.facts)
	}
	var inNet, announced int
	for _, e := range s.edges {
		switch e {
		case graph.RelInNetblock:
			inNet++
		case graph.RelAnnouncedBy:
			announced++
		}
	}
	if inNet != 1 || announced != 1 {
		t.Errorf("in_netblock=%d announced_by=%d, want 1 and 1", inNet, announced)
	}
}

func TestASNRejectsNonIP(t *testing.T) {
	a := &ASN{Client: srvThatFails(t), BaseURL: "http://127.0.0.1:0"}
	s := &recSink{}
	// A key that is not a bare address must be refused before any request is made.
	if err := a.Collect(context.Background(), graph.Entity{Type: graph.TypeIP, Key: "not-an-ip"}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.entities) != 0 {
		t.Errorf("no entities expected for a non-IP key, got %+v", s.entities)
	}
}

// srvThatFails returns a Doer that fails the test if it is ever called.
func srvThatFails(t *testing.T) Doer {
	t.Helper()
	return doerFunc(func(*http.Request) (*http.Response, error) {
		t.Error("HTTP request made for a key that should have been rejected")
		return nil, http.ErrHandlerTimeout
	})
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }
