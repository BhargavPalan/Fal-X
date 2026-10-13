package verify

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/storetest"
)

// fakeChecker scripts the network so Run is exercised without live DNS or HTTP.
type fakeChecker struct {
	resolves map[string]bool // a host absent from the map does not resolve (NXDOMAIN)
	gets     map[string]fakeResp
}

type fakeResp struct {
	body    []byte
	status  int
	reached bool
}

func (f fakeChecker) Get(_ context.Context, rawURL string) ([]byte, int, bool) {
	r, ok := f.gets[rawURL]
	if !ok {
		return nil, 0, false
	}
	return r.body, r.status, r.reached
}

func (f fakeChecker) Resolves(_ context.Context, host string) (bool, error) {
	return f.resolves[host], nil
}

func TestVerifyConfirmsTakeoverAndExposedFile(t *testing.T) {
	db := storetest.NewTestDB(t)
	ctx := context.Background()
	slug := fmt.Sprintf("verify-%d", time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })

	scoped, _ := db.WithOrg(ctx, orgID)

	// A host dangling onto an unclaimed Heroku app, and a served .git/config.
	gitURL := "http://web.example.com/.git/config"
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		host, err := graph.Resolve(ctx, tx, orgID, graph.TypeHost, "gone.example.com", "gone.example.com", 0)
		if err != nil {
			return err
		}
		if err := graph.AddFact(ctx, tx, host, "cname", "abandoned.herokuapp.com", "native/dns", false, 1, 0); err != nil {
			return err
		}
		_, err = graph.Resolve(ctx, tx, orgID, graph.TypeURL, gitURL, gitURL, 1)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	chk := fakeChecker{
		resolves: map[string]bool{}, // abandoned.herokuapp.com is absent, so it does not resolve
		gets: map[string]fakeResp{
			gitURL: {body: []byte("[core]\n\trepositoryformatversion = 0"), status: 200, reached: true},
		},
	}
	sum, err := Run(ctx, scoped, orgID, chk)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Confirmed != 2 || sum.Refuted != 0 {
		t.Errorf("summary = %+v, want 2 confirmed and 0 refuted", sum)
	}

	// Read back the verification facts and the re-asserted confirmed finding.
	verdicts := map[string]string{} // entity key -> verification value
	var confirmedTakeover bool
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT e.key, f.value FROM entity_fact f JOIN entity e ON e.id = f.entity_id
			WHERE f.key = 'verification'`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				return err
			}
			verdicts[k] = v
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `
			SELECT EXISTS (SELECT 1 FROM entity_fact f JOIN entity e ON e.id = f.entity_id
			WHERE e.key = 'gone.example.com' AND f.key = 'finding'
			AND f.value LIKE 'critical subdomain-takeover-confirmed%')`).Scan(&confirmedTakeover)
	}); err != nil {
		t.Fatal(err)
	}

	if v := verdicts["gone.example.com"]; !strings.HasPrefix(v, "confirmed takeover") {
		t.Errorf("host verification = %q, want it to start with 'confirmed takeover'", v)
	}
	if v := verdicts[gitURL]; !strings.HasPrefix(v, "confirmed exposed_git") {
		t.Errorf("url verification = %q, want it to start with 'confirmed exposed_git'", v)
	}
	if !confirmedTakeover {
		t.Error("expected a re-asserted 'critical subdomain-takeover-confirmed' finding on the host")
	}
}
