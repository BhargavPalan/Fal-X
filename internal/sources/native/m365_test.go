package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestM365MapsTenant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/getuserrealm.srf"):
			_, _ = w.Write([]byte(`{"NameSpaceType":"Managed","FederationBrandName":"Contoso","AuthURL":""}`))
		case strings.Contains(r.URL.Path, "openid-configuration"):
			_, _ = w.Write([]byte(`{"issuer":"https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	m := &M365{Client: srv.Client(), BaseURL: srv.URL}
	s := &recSink{}
	if err := m.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "contoso.com"}, s); err != nil {
		t.Fatal(err)
	}
	if !s.hasFact("m365", "managed") || !s.hasFact("m365_brand", "Contoso") {
		t.Errorf("expected m365 realm facts, facts=%+v", s.facts)
	}
	if !s.hasFact("azure_tenant_id", "12345678-1234-1234-1234-123456789abc") {
		t.Errorf("expected tenant GUID, facts=%+v", s.facts)
	}
}

func TestM365NonTenantIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/getuserrealm.srf") {
			_, _ = w.Write([]byte(`{"NameSpaceType":"Unknown"}`))
			return
		}
		http.Error(w, "bad", http.StatusBadRequest)
	}))
	defer srv.Close()

	m := &M365{Client: srv.Client(), BaseURL: srv.URL}
	s := &recSink{}
	if err := m.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "notm365.com"}, s); err != nil {
		t.Fatal(err)
	}
	if len(s.facts) != 0 {
		t.Errorf("a non-M365 domain must produce no facts, got %+v", s.facts)
	}
}
