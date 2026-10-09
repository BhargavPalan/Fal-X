package prioritize

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/store"
)

// testDB opens the integration database under the shared advisory lock, or skips.
// The key must match store.testLockKey.
func testDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("FALX_TEST_DSN"))
	if dsn == "" {
		t.Skip("set FALX_TEST_DSN to run database integration tests")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, store.DefaultOptions(dsn))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	lock, err := db.SQL().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.ExecContext(ctx, "SELECT pg_advisory_lock($1)", 7263001); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = lock.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", 7263001)
		_ = lock.Close()
	})
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

func TestRankOrdersByScoreAndUsesIntelligence(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	// Intelligence: one CVE that is known exploited, one only modelled likely.
	for _, q := range []string{
		"DELETE FROM cve_epss", "DELETE FROM cve_kev_cisa", "DELETE FROM cve",
		"INSERT INTO cve (cve_id) VALUES ('CVE-2021-44228'), ('CVE-2023-48795')",
		`INSERT INTO cve_kev_cisa (cve_id, vendor_project, product, vulnerability_name, date_added, known_ransomware)
		   VALUES ('CVE-2021-44228', 'Apache', 'Log4j2', 'Log4Shell', '2021-12-10', true)`,
		`INSERT INTO cve_epss (cve_id, epss, percentile, score_date) VALUES
		   ('CVE-2021-44228', 0.97, 0.999, '2026-10-08'), ('CVE-2023-48795', 0.9355, 0.998, '2026-10-08')`,
	} {
		if _, err := db.SQL().ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	slug := fmt.Sprintf("rank-%d", time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })

	scoped, _ := db.WithOrg(ctx, orgID)
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		add := func(identifier, value string) error {
			id, err := store.UpsertAsset(ctx, tx, orgID, "service", identifier)
			if err != nil {
				return err
			}
			return store.AddAttribute(ctx, tx, id, "finding", value, "scan/nuclei", 1)
		}
		for _, p := range [][2]string{
			{"a.example.test:22", `medium CVE-2023-48795 ["Vulnerable to Terrapin"]`},
			{"b.example.test:443", `low CVE-2021-44228`},
			{"c.example.test:22", `low ssh-weak-mac-algo`},
		} {
			if err := add(p[0], p[1]); err != nil {
				return err
			}
		}
		_, err := store.SetCriticality(ctx, tx, "c.example.test:22", 90)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	var ranked []Ranked
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		var err error
		ranked, err = Rank(ctx, tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(ranked) != 3 {
		t.Fatalf("ranked %d findings, want 3", len(ranked))
	}

	// A low-severity finding on a known-exploited CVE outranks a medium one that is
	// merely likely, and both outrank a plain low finding on a critical asset.
	if ranked[0].Asset != "b.example.test:443" || ranked[0].Result.Decision != Act {
		t.Errorf("first = %s %s, want the known-exploited finding with Act", ranked[0].Asset, ranked[0].Result.Decision)
	}
	if ranked[1].Asset != "a.example.test:22" || ranked[1].Result.Decision != Attend {
		t.Errorf("second = %s %s, want the high-EPSS finding with Attend", ranked[1].Asset, ranked[1].Result.Decision)
	}
	if ranked[2].Asset != "c.example.test:22" || ranked[2].Result.Decision != Track {
		t.Errorf("third = %s %s, want the plain finding with Track", ranked[2].Asset, ranked[2].Result.Decision)
	}
	if !ranked[0].Input.KEV || !ranked[0].Input.Ransomware || ranked[0].Input.EPSS == nil {
		t.Errorf("intelligence was not applied: %+v", ranked[0].Input)
	}
	if ranked[2].Input.Criticality != 90 {
		t.Errorf("operator criticality not read: %d", ranked[2].Input.Criticality)
	}
	// Every derivation adds up.
	for _, r := range ranked {
		sum := 0
		for _, w := range r.Result.Why {
			sum += w.Points
		}
		if sum != r.Result.Score {
			t.Errorf("%s: reasons sum to %d but score is %d", r.Asset, sum, r.Result.Score)
		}
	}
}

func TestSetCriticalityRejectsOutOfRange(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	err := db.InTx(ctx, func(tx *sql.Tx) error {
		_, err := store.SetCriticality(ctx, tx, "x", 101)
		return err
	})
	if err == nil {
		t.Error("criticality 101 accepted")
	}
}
