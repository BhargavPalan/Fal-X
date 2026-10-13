package native

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func resp(body string, status int) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

func TestTakeoverConfirmedBySignature(t *testing.T) {
	// The CNAME points at GitHub Pages and the body is the "unclaimed" signature: a
	// confirmed takeover even though the name resolves and answers HTTP.
	tk := &Takeover{
		Resolver: fakeResolver{cname: map[string]string{"gone.example.com": "myorg.github.io."}},
		Client: doerFunc(func(*http.Request) (*http.Response, error) {
			return resp("<html>There isn't a GitHub Pages site here.</html>", http.StatusNotFound), nil
		}),
	}
	s := &recSink{}
	if err := tk.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "gone.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasFact("finding", "high subdomain-takeover-confirmed GitHub Pages") {
		t.Errorf("expected a confirmed takeover finding, facts=%+v", s.facts)
	}
}

func TestTakeoverClaimedServiceIsNotFlagged(t *testing.T) {
	// CNAME to GitHub Pages but the site serves real content: it is claimed, no finding.
	tk := &Takeover{
		Resolver: fakeResolver{cname: map[string]string{"shop.example.com": "myorg.github.io."}},
		Client: doerFunc(func(*http.Request) (*http.Response, error) {
			return resp("<html><title>Welcome</title>real site</html>", http.StatusOK), nil
		}),
	}
	s := &recSink{}
	if err := tk.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "shop.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.facts) != 0 {
		t.Errorf("a claimed service must not be flagged, facts=%+v", s.facts)
	}
}

func TestTakeoverNonProviderCNAMEIgnored(t *testing.T) {
	tk := &Takeover{
		Resolver: fakeResolver{cname: map[string]string{"x.example.com": "y.example.net."}},
		Client: doerFunc(func(*http.Request) (*http.Response, error) {
			t.Error("must not fetch when the CNAME is not a claimable service")
			return nil, http.ErrHandlerTimeout
		}),
	}
	s := &recSink{}
	if err := tk.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "x.example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.facts) != 0 {
		t.Errorf("expected no findings, facts=%+v", s.facts)
	}
}
