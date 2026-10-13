package premium

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

func envCtx(name, key string) context.Context {
	return sources.WithEnv(context.Background(), sources.Env{Keys: map[string]string{name: key}})
}

func TestKeyedSubsParsesLabels(t *testing.T) {
	var gotAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("APIKEY")
		_, _ = w.Write([]byte(`{"subdomains":["www","mail","*.wild"]}`))
	}))
	defer srv.Close()

	k := &keyedSubs{
		name: "premium/test", keyName: "testkey", client: srv.Client(), baseURL: srv.URL,
		header: func(key string) map[string]string { return map[string]string{"APIKEY": key} },
		build: func(base, d string) string {
			return strings.TrimRight(base, "/") + "/v1/domain/" + d + "/subdomains"
		},
		parse: parseLabelList,
	}
	s := &recSink{}
	if err := k.Collect(envCtx("testkey", "secret"), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if gotAPIKey != "secret" {
		t.Errorf("key header = %q", gotAPIKey)
	}
	if !s.hasEntity(graph.TypeHost, "www.example.com") || !s.hasEntity(graph.TypeHost, "mail.example.com") {
		t.Errorf("expected hosts, entities=%+v", s.entities)
	}
	if !s.hasEntity(graph.TypeHost, "wild.example.com") {
		t.Errorf("a wildcard label should collapse to its base host, entities=%+v", s.entities)
	}
}

func TestKeyedSubsNoKeyIsSilent(t *testing.T) {
	k := &keyedSubs{name: "premium/test", keyName: "testkey", client: &http.Client{}}
	if k.Available(sources.Env{}) {
		t.Error("should be unavailable without a key")
	}
	s := &recSink{}
	if err := k.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.entities) != 0 {
		t.Errorf("no key, no emissions; got %+v", s.entities)
	}
}

func TestVirusTotalParsesFQDNs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"a.example.com"},{"id":"b.example.com"}]}`))
	}))
	defer srv.Close()

	vt := NewVirusTotal().(*keyedSubs)
	vt.client, vt.baseURL = srv.Client(), srv.URL
	s := &recSink{}
	if err := vt.Collect(envCtx("virustotal", "k"), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeHost, "a.example.com") || !s.hasEntity(graph.TypeHost, "b.example.com") {
		t.Errorf("expected VT FQDNs, entities=%+v", s.entities)
	}
}

func TestCensysParsesServicesWithBasicAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"result":{"services":[{"port":443,"service_name":"HTTP","certificate":"abc"}]}}`))
	}))
	defer srv.Close()

	c := &Censys{Client: srv.Client(), BaseURL: srv.URL}
	s := &recSink{}
	if err := c.Collect(envCtx("censys", "id:secret"), graph.Entity{Type: graph.TypeIP, Key: "192.0.2.1"}, s); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("expected Basic auth, got %q", gotAuth)
	}
	if !s.hasEntity(graph.TypeService, "192.0.2.1:443") || !s.hasEntity(graph.TypeCertificate, "abc") {
		t.Errorf("expected service + cert, entities=%+v", s.entities)
	}
	if !c.Available(sources.Env{Keys: map[string]string{"censys": "id:secret"}}) ||
		c.Available(sources.Env{Keys: map[string]string{"censys": "nokeysep"}}) {
		t.Error("Censys availability must require an id:secret key")
	}
}

func TestHunterParsesEmailsAndPeople(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"emails":[{"value":"cto@acme.com","first_name":"Ada","last_name":"Byte","position":"CTO"}]}}`))
	}))
	defer srv.Close()

	h := &Hunter{Client: srv.Client(), BaseURL: srv.URL}
	s := &recSink{}
	if err := h.Collect(envCtx("hunter", "k"), graph.Entity{Type: graph.TypeDomain, Key: "acme.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeEmail, "cto@acme.com") || !s.hasEntity(graph.TypePerson, "ada byte") {
		t.Errorf("expected email + person, entities=%+v", s.entities)
	}
	hasEmailEdge := false
	for _, e := range s.edges {
		if e == graph.RelHasEmail {
			hasEmailEdge = true
		}
	}
	if !hasEmailEdge {
		t.Errorf("expected a has_email edge, edges=%+v", s.edges)
	}
}

func TestFullHuntParsesHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"hosts":["a.acme.com","b.acme.com"]}`))
	}))
	defer srv.Close()

	fh := NewFullHunt().(*keyedSubs)
	fh.client, fh.baseURL = srv.Client(), srv.URL
	s := &recSink{}
	if err := fh.Collect(envCtx("fullhunt", "k"), graph.Entity{Type: graph.TypeDomain, Key: "acme.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasEntity(graph.TypeHost, "a.acme.com") || !s.hasEntity(graph.TypeHost, "b.acme.com") {
		t.Errorf("expected FullHunt hosts, entities=%+v", s.entities)
	}
}

func TestKeyedEngineParsers(t *testing.T) {
	if got := parseLeakIX([]byte(`[{"subdomain":"a.example.com"},{"subdomain":"b.example.com"}]`)); len(got) != 2 || got[0] != "a.example.com" {
		t.Errorf("parseLeakIX = %v", got)
	}
	if got := parseNetlas([]byte(`{"items":[{"data":{"domain":"a.example.com"}}]}`)); len(got) != 1 || got[0] != "a.example.com" {
		t.Errorf("parseNetlas = %v", got)
	}
	if got := parseZoomEye([]byte(`{"list":[{"name":"a.example.com"}]}`)); len(got) != 1 || got[0] != "a.example.com" {
		t.Errorf("parseZoomEye = %v", got)
	}
	if got := parseHostsField([]byte(`{"hosts":["a.example.com"]}`)); len(got) != 1 {
		t.Errorf("parseHostsField = %v", got)
	}
}

func TestGitHubParsesRepos(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"items":[{"repository":{"full_name":"acme/web"}},{"repository":{"full_name":"acme/web"}}]}`))
	}))
	defer srv.Close()

	g := &GitHub{Client: srv.Client(), BaseURL: srv.URL}
	s := &recSink{}
	if err := g.Collect(envCtx("github", "ghtok"), graph.Entity{Type: graph.TypeDomain, Key: "acme.com"}, s); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer ghtok" {
		t.Errorf("expected bearer token, got %q", gotAuth)
	}
	repos := 0
	for _, e := range s.entities {
		if e.t == graph.TypeRepository {
			repos++
		}
	}
	if repos != 1 { // deduped
		t.Errorf("expected 1 distinct repository, got %d (%+v)", repos, s.entities)
	}
}
