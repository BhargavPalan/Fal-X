package native

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// WebSpec discovers a host's machine-readable API surface: an exposed GraphQL endpoint
// with introspection enabled (which dumps the entire schema), and published
// OpenAPI/Swagger specifications (which list every endpoint and parameter). Both reveal
// attack surface a crawler never links to. It is active: it probes the host.
type WebSpec struct {
	Client Doer
}

// NewWebSpec returns a web-spec prober with a bounded client.
func NewWebSpec() *WebSpec {
	return &WebSpec{Client: &http.Client{Timeout: 10 * time.Second}}
}

// Capability marks it active, consuming a host and producing endpoints and findings.
func (w *WebSpec) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/webspec",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{graph.TypeEndpoint, graph.TypeFinding},
		Passive:  false,
		Heavy:    true, // several probes per host
		Cost:     2,
	}
}

// Available is always true; it uses the standard library.
func (w *WebSpec) Available(sources.Env) bool { return true }

var graphqlPaths = []string{"/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphiql"}

var specPaths = []string{
	"/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
	"/swagger/v1/swagger.json", "/.well-known/openapi.json", "/api/swagger.json", "/openapi.yaml",
}

const introspectionQuery = `{"query":"{__schema{queryType{name}}}"}`

// Collect probes the host once a working scheme is found.
func (w *WebSpec) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	host := in.Key
	base, ok := w.base(ctx, host)
	if !ok {
		return nil
	}
	self := sink.Entity(graph.TypeHost, host, host)
	w.probeGraphQL(ctx, base, self, sink)
	w.probeSpecs(ctx, base, self, sink)
	return nil
}

// base returns the scheme+host that answers on "/", or false.
func (w *WebSpec) base(ctx context.Context, host string) (string, bool) {
	for _, scheme := range []string{"https://", "http://"} {
		if _, status := w.req(ctx, http.MethodGet, scheme+host+"/", ""); status != 0 {
			return scheme + host, true
		}
	}
	return "", false
}

// probeGraphQL sends an introspection query to the common GraphQL paths; a schema in
// the response means introspection is enabled.
func (w *WebSpec) probeGraphQL(ctx context.Context, base string, self graph.Ref, sink sources.Sink) {
	for _, p := range graphqlPaths {
		body, status := w.req(ctx, http.MethodPost, base+p, introspectionQuery)
		if status != http.StatusOK || !bytes.Contains(body, []byte("__schema")) && !bytes.Contains(body, []byte("queryType")) {
			continue
		}
		u := base + p
		sink.Entity(graph.TypeURL, u, u)
		sink.Fact(self, "finding", "medium graphql-introspection-enabled", 0.8)
		sink.Fact(self, "exposure", "graphql_introspection", 0.8)
		return
	}
}

// probeSpecs fetches the common API-spec paths and lifts each declared path into an
// endpoint entity.
func (w *WebSpec) probeSpecs(ctx context.Context, base string, self graph.Ref, sink sources.Sink) {
	for _, p := range specPaths {
		body, status := w.req(ctx, http.MethodGet, base+p, "")
		if status != http.StatusOK || !looksLikeSpec(body) {
			continue
		}
		u := base + p
		ue := sink.Entity(graph.TypeURL, u, u)
		sink.Fact(self, "finding", "low exposed-api-spec", 0.7)
		sink.Fact(self, "exposure", "exposed_api_spec", 0.7)
		for _, path := range specPathsOf(body) {
			ep := sink.Entity(graph.TypeEndpoint, path, path)
			sink.Edge(ue, ep, graph.RelHasEndpoint, 0.8)
		}
		return
	}
}

// looksLikeSpec reports whether a body is an OpenAPI/Swagger document.
func looksLikeSpec(body []byte) bool {
	return bytes.Contains(body, []byte(`"swagger"`)) || bytes.Contains(body, []byte(`"openapi"`)) ||
		(bytes.Contains(body, []byte(`"paths"`)) && bytes.Contains(body, []byte(`"info"`)))
}

// specPathsOf extracts the declared endpoint paths from an OpenAPI document.
func specPathsOf(body []byte) []string {
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	out := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
		if len(out) >= 500 {
			break
		}
	}
	return out
}

// req issues one request (body for POST) and returns a bounded body and status, or 0.
func (w *WebSpec) req(ctx context.Context, method, rawURL, reqBody string) ([]byte, int) {
	var rdr *strings.Reader
	if reqBody != "" {
		rdr = strings.NewReader(reqBody)
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequestWithContext(ctx, method, rawURL, rdr)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, rawURL, nil)
	}
	if err != nil {
		return nil, 0
	}
	req.Header.Set("User-Agent", "fal-x")
	if reqBody != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := w.Client.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	body := readBounded(resp.Body, 512<<10)
	return body, resp.StatusCode
}
