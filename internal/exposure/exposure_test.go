package exposure

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

func TestTakeoverProvider(t *testing.T) {
	cases := map[string]string{
		"myorg.github.io":             "GitHub Pages",
		"abandoned.herokuapp.com":     "Heroku",
		"bucket.s3.amazonaws.com":     "Amazon S3",
		"x.blob.core.windows.net":     "Azure Blob Storage",
		"nothing-special.example.com": "",
		"":                            "",
	}
	for cname, want := range cases {
		if got := TakeoverProvider(cname); got != want {
			t.Errorf("TakeoverProvider(%q) = %q, want %q", cname, got, want)
		}
	}
}

func TestExposureWritesFindings(t *testing.T) {
	db := storetest.NewTestDB(t)
	ctx := context.Background()
	slug := fmt.Sprintf("expo-%d", time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })

	scoped, _ := db.WithOrg(ctx, orgID)
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		cert, err := graph.Resolve(ctx, tx, orgID, graph.TypeCertificate, "deadbeef", "old cert", 0)
		if err != nil {
			return err
		}
		if err := graph.AddFact(ctx, tx, cert, "expired", "true", "native/tls", true, 1, 0); err != nil {
			return err
		}
		host, err := graph.Resolve(ctx, tx, orgID, graph.TypeHost, "gone.example.com", "gone.example.com", 0)
		if err != nil {
			return err
		}
		return graph.AddFact(ctx, tx, host, "cname", "abandoned.herokuapp.com", "native/dns", false, 1, 0)
	}); err != nil {
		t.Fatal(err)
	}

	if err := Run(ctx, scoped, orgID); err != nil {
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

	var gotCert, gotTakeover bool
	for _, f := range findings {
		if strings.Contains(f, "expired-certificate") {
			gotCert = true
		}
		if strings.Contains(f, "subdomain-takeover Heroku") {
			gotTakeover = true
		}
	}
	if !gotCert {
		t.Errorf("expected an expired-certificate finding, got %v", findings)
	}
	if !gotTakeover {
		t.Errorf("expected a Heroku takeover finding, got %v", findings)
	}
}
