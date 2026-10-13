package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

func TestRDAPExtractsDatesAndEmails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"events": [
				{"eventAction":"registration","eventDate":"1997-09-15T04:00:00Z"},
				{"eventAction":"expiration","eventDate":"2028-09-14T04:00:00Z"}
			],
			"entities": [
				{"vcardArray":["vcard",[["email",{},"text","abuse@registrar.example"]]]}
			]
		}`))
	}))
	defer srv.Close()

	r := &RDAP{Client: srv.Client(), BaseURL: srv.URL}
	s := &recSink{}
	if err := r.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, s); err != nil {
		t.Fatal(err)
	}

	var reg, exp, email bool
	for _, f := range s.facts {
		switch {
		case f.key == "registered" && f.value == "1997-09-15T04:00:00Z":
			reg = true
		case f.key == "expires" && f.value == "2028-09-14T04:00:00Z":
			exp = true
		case f.key == "rdap_email" && f.value == "abuse@registrar.example":
			email = true
		}
	}
	if !reg || !exp {
		t.Errorf("expected registered and expires facts, got %+v", s.facts)
	}
	if !email {
		t.Errorf("expected rdap_email fact, got %+v", s.facts)
	}
	if !s.hasEntity(graph.TypeEmail, "abuse@registrar.example") {
		t.Errorf("expected an email entity, got %+v", s.entities)
	}
}
