package native

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

// stubResp builds an HTTP response with a status and body for a fake Doer.
func stubResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestVhostReportsDistinctVirtualHosts(t *testing.T) {
	doer := doerFunc(func(r *http.Request) (*http.Response, error) {
		switch r.Host {
		case "www.example.com":
			return stubResp(200, "the public homepage, a good deal longer than the catch-all page"), nil
		case "dev.example.com":
			return stubResp(200, "INTERNAL DEV ENVIRONMENT"), nil // 200 vs the 404 catch-all: distinct
		default:
			return stubResp(404, "not found"), nil // the catch-all for unknown vhosts (incl. admin)
		}
	})
	v := &Vhost{Client: doer}
	s := &recSink{}
	if err := v.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "www.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeHost, "dev.example.com") || !s.hasFact("vhost", "dev.example.com") {
		t.Errorf("expected dev.example.com to be reported as a virtual host; got %+v", s.facts)
	}
	if s.hasEntity(graph.TypeHost, "admin.example.com") {
		t.Error("admin.example.com matches the catch-all and must not be reported")
	}
}

func TestVhostAbortsWhenBaselineFails(t *testing.T) {
	// The server is up (workingScheme succeeds) but the baseline probe transiently fails;
	// every candidate would then look distinct, so nothing must be emitted.
	doer := doerFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasPrefix(r.Host, "falx-vhost-baseline-"):
			return nil, io.ErrUnexpectedEOF // the baseline request fails
		default:
			return stubResp(200, "a page"), nil // base probe and every candidate answer 200
		}
	})
	v := &Vhost{Client: doer}
	s := &recSink{}
	if err := v.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "www.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.entities) != 0 || len(s.facts) != 0 {
		t.Errorf("a failed baseline must fabricate no virtual hosts, got %+v / %+v", s.entities, s.facts)
	}
}

func TestVhostSkipsWhenNoWebServer(t *testing.T) {
	// Nothing answers: workingScheme fails and no candidate is probed.
	doer := doerFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF })
	v := &Vhost{Client: doer}
	s := &recSink{}
	if err := v.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "www.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.entities) != 0 || len(s.facts) != 0 {
		t.Errorf("a host with no web server must emit nothing, got %+v / %+v", s.entities, s.facts)
	}
}
