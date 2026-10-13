package origin

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/store"
	"github.com/BhargavPalan/Fal-X/internal/storetest"
)

func TestRegisteredDomain(t *testing.T) {
	for in, want := range map[string]string{
		"www.example.com":   "example.com",
		"a.b.c.example.com": "example.com",
		"example.com":       "example.com",
	} {
		if got := registeredDomain(in); got != want {
			t.Errorf("registeredDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeProber returns a fixed signature for the fronted host and matches it only on the
// true origin IP.
type fakeProber struct {
	host, originIP, sig string
}

func (f fakeProber) Signature(_ context.Context, host string) (string, bool) {
	if host == f.host {
		return f.sig, true
	}
	return "", false
}
func (f fakeProber) Probe(_ context.Context, ip, host string) (string, bool) {
	if ip == f.originIP && host == f.host {
		return f.sig, true
	}
	return "", false // other candidates serve something different
}

func TestOriginDiscovery(t *testing.T) {
	db := storetest.NewTestDB(t)
	ctx := context.Background()
	slug := fmt.Sprintf("origin-%d", time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })

	scoped, _ := db.WithOrg(ctx, orgID)
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		www, err := graph.Resolve(ctx, tx, orgID, graph.TypeHost, "www.example.com", "www.example.com", 0)
		if err != nil {
			return err
		}
		if err := graph.AddFact(ctx, tx, www, "cdn", "Cloudflare", "native/cdncheck", false, 1, 0); err != nil {
			return err
		}
		cdnIP, err := graph.Resolve(ctx, tx, orgID, graph.TypeIP, "192.0.2.1", "192.0.2.1", 0)
		if err != nil {
			return err
		}
		if err := graph.AddEdge(ctx, tx, orgID, www, cdnIP, graph.RelResolvesTo, graph.TypeHost, graph.TypeIP, 1); err != nil {
			return err
		}
		// A sibling in the same domain exposes the real origin IP directly.
		mail, err := graph.Resolve(ctx, tx, orgID, graph.TypeHost, "mail.example.com", "mail.example.com", 0)
		if err != nil {
			return err
		}
		originIP, err := graph.Resolve(ctx, tx, orgID, graph.TypeIP, "198.51.100.5", "198.51.100.5", 0)
		if err != nil {
			return err
		}
		return graph.AddEdge(ctx, tx, orgID, mail, originIP, graph.RelResolvesTo, graph.TypeHost, graph.TypeIP, 1)
	}); err != nil {
		t.Fatal(err)
	}

	prober := fakeProber{host: "www.example.com", originIP: "198.51.100.5", sig: "match"}
	if err := Run(ctx, scoped, orgID, prober); err != nil {
		t.Fatal(err)
	}

	var findings []string
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		rows, err := store.ListFindings(ctx, tx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			findings = append(findings, r.Value)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f, "origin-ip-exposed 198.51.100.5") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an origin-ip-exposed finding, got %v", findings)
	}
}
