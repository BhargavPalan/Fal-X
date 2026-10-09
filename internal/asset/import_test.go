package asset

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/run"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// testDB opens the integration database, or skips. It mirrors the store tests:
// the suite needs FALX_TEST_DSN and says so when it is absent.
func testDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("FALX_TEST_DSN"))
	if dsn == "" {
		t.Skip("set FALX_TEST_DSN to run database integration tests")
	}
	db, err := store.Open(context.Background(), store.DefaultOptions(dsn))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Serialize with internal/store's tests, which drop the schema. The key must
	// match testLockKey there.
	ctx := context.Background()
	lock, err := db.SQL().Conn(ctx)
	if err != nil {
		t.Fatalf("lock connection: %v", err)
	}
	if _, err := lock.ExecContext(ctx, "SELECT pg_advisory_lock($1)", 7263001); err != nil {
		t.Fatalf("advisory lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = lock.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", 7263001)
		_ = lock.Close()
	})

	if _, err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// uniq makes a name no other test run has used, so repeated runs against one
// database never collide.
func uniq(prefix string) string { return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()) }

// fixtureRun writes a real run directory with synthetic data only.
func fixtureRun(t *testing.T, target string) string {
	t.Helper()
	r, err := run.Init(t.TempDir(), target, "20261003-123456")
	if err != nil {
		t.Fatal(err)
	}
	r.SetTarget(target)
	r.SetProfile("normal")
	r.SetMode("domain")
	r.SetToolVersion("httpx", "v1.12.0")
	r.SetToolVersion("nuclei", "v3.11.1")
	r.SetScope("example.com\n", "")
	_ = r.Stage("subs", func() error { return nil })
	_ = r.Stage("http", func() error { return nil })
	_ = r.Stage("scan", func() error { return nil })
	if err := r.Finalise(); err != nil {
		t.Fatal(err)
	}
	put := func(rel, body string) {
		p := filepath.Join(r.Dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put("2-subs/subdomains.txt", "www."+target+"\napi."+target+"\n")
	put("3-resolve/resolved.txt", "www."+target+"\n")
	put("3-resolve/ips.txt", "192.0.2.10\n")
	put("4-ports/open.txt", "www."+target+":80\nwww."+target+":22\n")
	put("5-http/probe.json", `{"url":"http://www.`+target+`","status_code":200,"title":"Home","webserver":"nginx","tech":["Nginx","PHP"]}`+"\n")
	put("6-content/urls.txt", "http://www."+target+"/a\nhttp://www."+target+"/b\nhttp://www."+target+"/a\n")
	put("6-content/endpoints.txt", "http://www."+target+"/a\n")
	put("7-scan/findings.json",
		"[ssh-weak-mac] [javascript] [low] www."+target+":22\n"+
			"[exposed-listing:files] [http] [medium] http://www."+target+"/a [\"index\"]\n")
	return r.Dir
}

func countAssets(t *testing.T, db *store.DB, orgID int64) (n int) {
	t.Helper()
	scoped, _ := db.WithOrg(context.Background(), orgID)
	if err := scoped.InTx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), "SELECT count(*) FROM asset").Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func cleanupOrg(t *testing.T, db *store.DB, slug string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = db.SQL().ExecContext(context.Background(), "DELETE FROM org WHERE slug = $1", slug)
	})
}

func TestImportKeepsEverythingTheRunFound(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	slug := uniq("imp")
	cleanupOrg(t, db, slug)

	sum, err := Import(ctx, db, slug, fixtureRun(t, "example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Findings != 2 {
		t.Errorf("findings = %d, want 2", sum.Findings)
	}
	// 2 subdomains + 1 host + 1 address + 2 services + 3 urls = 9 distinct
	// assets. The summary must count each once, not once per sighting (the crawl,
	// the endpoint list and a finding all name /a).
	if sum.Assets != 9 {
		t.Errorf("summary says %d assets, want 9 distinct", sum.Assets)
	}

	orgID, _ := db.EnsureOrg(ctx, slug, slug)
	scoped, _ := db.WithOrg(ctx, orgID)
	kinds := map[string]int{}
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		rows, err := store.ListAssets(ctx, tx, "", 1000)
		for _, r := range rows {
			kinds[r.Kind]++
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// 2 subdomains, 1 resolved host, 1 address, 2 services, and 3 distinct URLs:
	// the live page, /a and /b. The duplicate /a, the endpoint list and the
	// finding on /a all collapse onto existing rows.
	want := map[string]int{"domain": 2, "host": 1, "ip": 1, "service": 2, "url": 3}
	for k, v := range want {
		if kinds[k] != v {
			t.Errorf("%s assets = %d, want %d (all kinds: %v)", k, kinds[k], v, kinds)
		}
	}

	// The tool versions the run recorded reach the database.
	var versions string
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT tool_versions::text FROM run").Scan(&versions)
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(versions, `"httpx": "v1.12.0"`) || !strings.Contains(versions, `"nuclei": "v3.11.1"`) {
		t.Errorf("tool versions not stored: %s", versions)
	}

	var detail []store.AssetDetail
	_ = scoped.InTx(ctx, func(tx *sql.Tx) error {
		var err error
		detail, err = store.GetAsset(ctx, tx, "http://www.example.test")
		return err
	})
	if len(detail) != 1 {
		t.Fatalf("GetAsset returned %d rows", len(detail))
	}
	attrs := map[string]int{}
	for _, a := range detail[0].Attributes {
		attrs[a.Key]++
	}
	if attrs["status"] != 1 || attrs["title"] != 1 || attrs["server"] != 1 || attrs["tech"] != 2 {
		t.Errorf("live page attributes wrong: %v", attrs)
	}
}

func TestImportIsIdempotent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	slug := uniq("idem")
	cleanupOrg(t, db, slug)
	dir := fixtureRun(t, "example.test")

	if _, err := Import(ctx, db, slug, dir); err != nil {
		t.Fatal(err)
	}
	orgID, _ := db.EnsureOrg(ctx, slug, slug)
	first := countAssets(t, db, orgID)

	if _, err := Import(ctx, db, slug, dir); err != nil {
		t.Fatalf("second import: %v", err)
	}
	if got := countAssets(t, db, orgID); got != first {
		t.Errorf("assets after re-import = %d, want %d", got, first)
	}

	scoped, _ := db.WithOrg(ctx, orgID)
	var runs, stages int
	_ = scoped.InTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM run").Scan(&runs); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SELECT count(*) FROM run_stage").Scan(&stages)
	})
	if runs != 1 || stages != 3 {
		t.Errorf("runs=%d stages=%d after two imports, want 1 and 3", runs, stages)
	}
}

func TestImportDoesNotCrossTenants(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a, b := uniq("ta"), uniq("tb")
	cleanupOrg(t, db, a)
	cleanupOrg(t, db, b)

	if _, err := Import(ctx, db, a, fixtureRun(t, "alpha.test")); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(ctx, db, b, fixtureRun(t, "beta.test")); err != nil {
		t.Fatal(err)
	}
	idA, _ := db.EnsureOrg(ctx, a, a)
	idB, _ := db.EnsureOrg(ctx, b, b)

	scopedA, _ := db.WithOrg(ctx, idA)
	_ = scopedA.InTx(ctx, func(tx *sql.Tx) error {
		rows, err := store.ListAssets(ctx, tx, "", 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if strings.Contains(r.Identifier, "beta.test") {
				t.Errorf("tenant A can see tenant B's asset %q", r.Identifier)
			}
		}
		if len(rows) == 0 {
			t.Error("tenant A sees nothing of its own")
		}
		return nil
	})
	if countAssets(t, db, idA) == 0 || countAssets(t, db, idB) == 0 {
		t.Error("a tenant has no assets")
	}
}

func TestFindingAssetKinds(t *testing.T) {
	cases := map[string]string{
		"http://example.test/x": KindURL,
		"192.0.2.10:22":         KindService,
		"example.test:22":       KindService,
		"example.test":          KindHost,
	}
	for in, want := range cases {
		if got, _ := findingAsset(in); got != want {
			t.Errorf("findingAsset(%q) = %q, want %q", in, got, want)
		}
	}
}
