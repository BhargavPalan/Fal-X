package store

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLoadMigrations checks the embedded set without needing a database.
//
// Every migration must have both directions. A migration that cannot be rolled
// back leaves a failed deployment unrecoverable without a manual restore, so it
// is a build-time error rather than something to discover in production.
func TestLoadMigrations(t *testing.T) {
	ms, err := LoadMigrations()
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("no migrations embedded")
	}

	seen := map[int]bool{}
	for i, m := range ms {
		if m.Version <= 0 {
			t.Errorf("migration %d: version must be positive", i)
		}
		if m.Name == "" {
			t.Errorf("migration %04d: empty name", m.Version)
		}
		if strings.TrimSpace(m.Up) == "" {
			t.Errorf("migration %04d_%s: empty up body", m.Version, m.Name)
		}
		if strings.TrimSpace(m.Down) == "" {
			t.Errorf("migration %04d_%s: empty down body", m.Version, m.Name)
		}
		if seen[m.Version] {
			t.Errorf("duplicate version %04d", m.Version)
		}
		seen[m.Version] = true

		if i > 0 && m.Version <= ms[i-1].Version {
			t.Errorf("migrations out of order: %04d after %04d", m.Version, ms[i-1].Version)
		}
	}
}

// TestChecksumNormalisesLineEndings pins the behaviour that keeps the drift
// check from firing on a CRLF checkout.
func TestChecksumNormalisesLineEndings(t *testing.T) {
	lf := "CREATE TABLE a (id int);\nCREATE TABLE b (id int);\n"
	crlf := strings.ReplaceAll(lf, "\n", "\r\n")
	trailing := "CREATE TABLE a (id int);   \nCREATE TABLE b (id int);\t\n"

	if got, want := checksum(crlf), checksum(lf); got != want {
		t.Errorf("line endings changed the checksum: %s vs %s", got, want)
	}
	if got, want := checksum(trailing), checksum(lf); got != want {
		t.Errorf("trailing whitespace changed the checksum: %s vs %s", got, want)
	}
	if checksum(lf) == checksum("CREATE TABLE a (id int);\n") {
		t.Error("different bodies produced the same checksum")
	}
}

// testDSN returns the DSN for integration tests, or skips.
//
// Integration tests are opt-in through FALX_TEST_DSN so `go test ./...` works
// on a machine with no Postgres. The CI job sets it.
func testDSN(t *testing.T) string {
	t.Helper()
	if v := strings.TrimSpace(os.Getenv("FALX_TEST_DSN")); v != "" {
		return v
	}
	if v := DSNFromEnv(); v != "" {
		return v
	}
	t.Skip("set FALX_TEST_DSN to run database integration tests")
	return ""
}

// newTestDB opens a connection and confirms the server actually serves a
// connection, not just accepts the socket.
func newTestDB(t *testing.T) *DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := Open(ctx, DefaultOptions(testDSN(t)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Go runs test packages in parallel and they share this one database, while
	// some tests here tear the whole schema down. Hold a database-wide advisory
	// lock for the life of the test so nothing else (internal/asset's tests take
	// the same key) runs against a schema that is being dropped.
	lock, err := db.SQL().Conn(ctx)
	if err != nil {
		t.Fatalf("lock connection: %v", err)
	}
	if _, err := lock.ExecContext(ctx, "SELECT pg_advisory_lock($1)", testLockKey); err != nil {
		t.Fatalf("advisory lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = lock.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", testLockKey)
		_ = lock.Close()
	})
	return db
}

// testLockKey is the advisory lock every database test takes. It is repeated in
// internal/asset's tests, which must use the same value.
const testLockKey = 7263001

// TestMigrateAppliesAndRollsBack is the schema gate: every migration
// applies to an empty database, reverts cleanly, and re-applies.
func TestMigrateAppliesAndRollsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := newTestDB(t)
	ctx := context.Background()

	// Start from empty regardless of the database's current state, so the test
	// is order independent when run against a shared instance.
	if _, err := db.Rollback(ctx, 0); err != nil {
		t.Fatalf("initial rollback: %v", err)
	}

	applied, err := db.Migrate(ctx)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ms, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if applied != len(ms) {
		t.Errorf("applied %d migrations, want %d", applied, len(ms))
	}

	status, err := db.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	for _, st := range status {
		if !st.Applied {
			t.Errorf("migration %04d_%s reported not applied after Migrate", st.Version, st.Name)
		}
		if st.Drift {
			t.Errorf("migration %04d_%s reports drift immediately after apply", st.Version, st.Name)
		}
		if st.SchemaDrift {
			t.Errorf("migration %04d_%s reports schema drift immediately after apply", st.Version, st.Name)
		}
	}

	// Tables the core migration must create.
	for _, want := range []string{
		"org", "app_user", "scope_snapshot",
		"run", "run_stage",
		"asset", "asset_attribute", "asset_observation",
		"schema_migration",
	} {
		var n int
		err := db.SQL().QueryRowContext(ctx,
			"SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name=$1",
			want).Scan(&n)
		if err != nil {
			t.Fatalf("check table %s: %v", want, err)
		}
		if n != 1 {
			t.Errorf("table %s: found %d, want 1", want, n)
		}
	}

	// Row-level security must be enabled on every tenant-scoped table.
	var policies int
	// One policy per tenant-scoped table: org itself is deliberately not
	// covered, since a session must be able to look up its own org row before
	// it has an org id.
	wantPolicies := 7
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT count(*) FROM pg_policies WHERE schemaname='public'").Scan(&policies); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if policies != wantPolicies {
		t.Errorf("row-level security policies: got %d, want %d", policies, wantPolicies)
	}

	// Every table except the deliberately global ones (org, the schema ledger, and
	// the vulnerability reference data, which is the same for every tenant) must
	// have RLS
	// switched on and forced. A table with no policy is silently readable by every
	// tenant, which is the exact failure this layer exists to prevent. The list is
	// derived from the database rather than written out, because a hand-written
	// list is how run_stage was missed: a new table is checked without anyone
	// remembering to add it here.
	rows, err := db.SQL().QueryContext(ctx, `
		SELECT relname, relrowsecurity, relforcerowsecurity
		FROM pg_class
		WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'
		  AND relname NOT IN ('org', 'schema_fingerprint', 'schema_migration',
		                      'cve', 'cve_kev_cisa', 'cve_epss', 'cve_nvd', 'source_watermark')
		ORDER BY relname`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()
	checked := 0
	for rows.Next() {
		var name string
		var enabled, forced bool
		if err := rows.Scan(&name, &enabled, &forced); err != nil {
			t.Fatal(err)
		}
		checked++
		if !enabled {
			t.Errorf("table %s has row-level security disabled", name)
		}
		if !forced {
			t.Errorf("table %s does not FORCE row-level security, so its owner bypasses it", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if checked != 7 {
		t.Errorf("checked %d tenant tables, want 7", checked)
	}

	reverted, err := db.Rollback(ctx, 0)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if reverted != len(ms) {
		t.Errorf("reverted %d, want %d", reverted, len(ms))
	}

	var left int
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name <> 'schema_migration'").
		Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("rollback left %d tables behind", left)
	}

	// Re-apply so the database is left in a usable state.
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("re-Migrate: %v", err)
	}
}

// TestMigrateIsIdempotent pins that a second Migrate applies nothing.
func TestMigrateIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := newTestDB(t)
	ctx := context.Background()

	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	applied, err := db.Migrate(ctx)
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if applied != 0 {
		t.Errorf("second Migrate applied %d migrations, want 0", applied)
	}
}

// TestSchemaFingerprintDetectsOutOfBandChange is the guard on tenant
// isolation.
//
// The ledger checksums only notice a migration file being edited after the
// fact. These cases change the live database directly, which is the change that
// matters: each one removes a row-level security policy or flag, and if that
// went unnoticed then one organisation could read another's rows while every
// migration still reported itself as applied.
func TestSchemaFingerprintDetectsOutOfBandChange(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cases := []struct {
		name   string
		tamper string
		// restore is a list rather than a single statement so each case can be
		// made idempotent. The subtest restores in the middle to prove the
		// check is not a one-way alarm, then the cleanup restores again; a
		// restore that fails the second time would mask the real result.
		restore []string
	}{
		{
			name:   "dropped policy",
			tamper: "DROP POLICY asset_rls ON asset",
			restore: []string{
				"DROP POLICY IF EXISTS asset_rls ON asset",
				"CREATE POLICY asset_rls ON asset USING (org_id = current_org_id())",
			},
		},
		{
			name:    "disabled row level security",
			tamper:  "ALTER TABLE asset DISABLE ROW LEVEL SECURITY",
			restore: []string{"ALTER TABLE asset ENABLE ROW LEVEL SECURITY"},
		},
		{
			name:    "cleared force flag",
			tamper:  "ALTER TABLE run NO FORCE ROW LEVEL SECURITY",
			restore: []string{"ALTER TABLE run FORCE ROW LEVEL SECURITY"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			ctx := context.Background()

			// Land on a known good schema, then re-capture so the recorded
			// fingerprint describes the state this case starts from.
			if _, err := db.Rollback(ctx, 0); err != nil {
				t.Fatalf("rollback: %v", err)
			}
			if _, err := db.Migrate(ctx); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			if err := db.CaptureFingerprint(ctx); err != nil {
				t.Fatalf("capture fingerprint: %v", err)
			}

			restore := func() {
				t.Helper()
				for _, stmt := range tc.restore {
					if _, err := db.SQL().ExecContext(context.Background(), stmt); err != nil {
						t.Fatalf("restore %q: %v", stmt, err)
					}
				}
				if err := db.CaptureFingerprint(context.Background()); err != nil {
					t.Fatalf("recapture fingerprint: %v", err)
				}
			}

			if _, err := db.SQL().ExecContext(ctx, tc.tamper); err != nil {
				t.Fatalf("tamper: %v", err)
			}
			t.Cleanup(restore)

			status, err := db.Status(ctx)
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			drifted := false
			for _, st := range status {
				if st.SchemaDrift {
					drifted = true
				}
				if st.Drift {
					t.Errorf("file drift reported for %s; this case changes the database, not the migration", st.Name)
				}
			}
			if !drifted {
				t.Error("Status reported no schema drift after the live schema changed")
			}

			// Restoring the schema must clear the report again, otherwise the
			// check would be a one-way alarm nobody trusts.
			restore()

			status, err = db.Status(ctx)
			if err != nil {
				t.Fatalf("Status after restore: %v", err)
			}
			for _, st := range status {
				if st.SchemaDrift {
					t.Error("schema drift still reported after the schema was restored")
				}
			}
		})
	}
}

// TestSchemaFingerprintIsStable pins that the fingerprint depends only on the
// schema shape, not on query order, so it does not flap between runs.
func TestSchemaFingerprintIsStable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := newTestDB(t)
	ctx := context.Background()

	first, err := schemaFingerprint(ctx, db)
	if err != nil {
		t.Fatalf("schemaFingerprint: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := schemaFingerprint(ctx, db)
		if err != nil {
			t.Fatalf("schemaFingerprint: %v", err)
		}
		if again != first {
			t.Fatalf("fingerprint is unstable: %s then %s", first, again)
		}
	}
	if first == "" {
		t.Error("fingerprint is empty; an empty fingerprint compares equal to anything")
	}
}

// TestRowLevelSecurityIsolatesTenants is the multi-tenancy gate from the plan.
//
// Two tenants insert assets, then each reads back only its own. This is the
// property that makes Postgres, rather than a Go-side WHERE clause, the
// security boundary.
func TestRowLevelSecurityIsolatesTenants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := newTestDB(t)
	ctx := context.Background()

	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	suffix := time.Now().UnixNano()

	ids := map[string]int64{}
	for _, name := range []string{"alpha", "beta"} {
		var id int64
		err := db.SQL().QueryRowContext(ctx,
			"INSERT INTO org (slug, name) VALUES ($1, $2) RETURNING id",
			name+"-"+itoa(suffix), name).Scan(&id)
		if err != nil {
			t.Fatalf("insert org %s: %v", name, err)
		}
		ids[name] = id
	}
	t.Cleanup(func() {
		_, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE id = ANY($1)", []int64{ids["alpha"], ids["beta"]})
	})

	for name, id := range ids {
		scoped, err := db.WithOrg(ctx, id)
		if err != nil {
			t.Fatalf("WithOrg %s: %v", name, err)
		}
		err = scoped.InTx(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx,
				"INSERT INTO asset (org_id, kind, identifier) VALUES ($1, 'host', $2)",
				id, name+".example.test")
			return err
		})
		if err != nil {
			t.Fatalf("insert asset for %s: %v", name, err)
		}
	}

	for name, id := range ids {
		scoped, err := db.WithOrg(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		err = scoped.InTx(ctx, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, "SELECT count(*) FROM asset").Scan(&n)
		})
		if err != nil {
			t.Fatalf("count assets for %s: %v", name, err)
		}
		if n != 1 {
			t.Errorf("tenant %s sees %d assets, want 1 (row-level security not applied)", name, n)
		}
	}
}

func TestOpenRejectsEmptyDSN(t *testing.T) {
	_, err := Open(context.Background(), Options{DSN: "  "})
	if err == nil {
		t.Fatal("expected an error for an empty DSN")
	}
	if !strings.Contains(err.Error(), "empty DSN") {
		t.Errorf("error should mention the empty DSN, got: %v", err)
	}
}

// TestDSNFromEnv covers the lookup order.
func TestDSNFromEnv(t *testing.T) {
	for _, k := range []string{"FALX_DSN", "DATABASE_URL", "PGDSN"} {
		t.Setenv(k, "")
	}
	if got := DSNFromEnv(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}

	t.Setenv("DATABASE_URL", "postgres://b/")
	if got := DSNFromEnv(); got != "postgres://b/" {
		t.Errorf("DATABASE_URL not honoured: %q", got)
	}

	t.Setenv("FALX_DSN", "postgres://a/")
	if got := DSNFromEnv(); got != "postgres://a/" {
		t.Errorf("FALX_DSN should win: %q", got)
	}

	t.Setenv("FALX_DSN", "   ")
	if got := DSNFromEnv(); got != "postgres://b/" {
		t.Errorf("blank FALX_DSN should fall through, got %q", got)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		return "-" + string(buf)
	}
	return string(buf)
}

var _ = os.Getenv

// TestWithOrgDoesNotLeakAcrossPooledConnections pins that a tenant setting does
// not stick to whichever pooled connection happened to run it.
//
// A session-level set_config on the shared pool would live on one physical
// connection. A second connection
// then ran with no org (a tenant seeing nothing), and a connection last used for
// tenant B could serve tenant A (a tenant seeing another's rows). Holding one
// connection open forces the pool to use a second, which is what exposes it.
func TestWithOrgDoesNotLeakAcrossPooledConnections(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	suffix := time.Now().UnixNano()
	ids := map[string]int64{}
	for _, name := range []string{"gamma", "delta"} {
		var id int64
		if err := db.SQL().QueryRowContext(ctx,
			"INSERT INTO org (slug, name) VALUES ($1, $2) RETURNING id",
			name+"-"+itoa(suffix), name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids[name] = id
	}
	t.Cleanup(func() {
		_, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE id = ANY($1)", []int64{ids["gamma"], ids["delta"]})
	})

	a, err := db.WithOrg(ctx, ids["gamma"])
	if err != nil {
		t.Fatal(err)
	}
	b, err := db.WithOrg(ctx, ids["delta"])
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]*DB{"gamma": a, "delta": b} {
		if err := d.InTx(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx,
				"INSERT INTO asset (org_id, kind, identifier) VALUES ($1, 'host', $2)",
				ids[name], name+".example.test")
			return err
		}); err != nil {
			t.Fatalf("insert for %s: %v", name, err)
		}
	}

	// Occupy one connection so the pool has to open another.
	held, err := db.SQL().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	for round := 0; round < 20; round++ {
		for name, d := range map[string]*DB{"gamma": a, "delta": b} {
			var host string
			if err := d.InTx(ctx, func(tx *sql.Tx) error {
				return tx.QueryRowContext(ctx, "SELECT identifier FROM asset").Scan(&host)
			}); err != nil {
				t.Fatalf("round %d, %s: %v", round, name, err)
			}
			if host != name+".example.test" {
				t.Fatalf("round %d: tenant %s read %q, want its own row", round, name, host)
			}
		}
	}
}

// TestRunStageIsTenantIsolated pins that one tenant cannot read another's run
// stages. run_stage carries no org_id of its own, so it has to be isolated
// through its parent run; the first migration enabled row-level security on every
// other tenant table and missed this one, so every tenant could read every stage.
func TestRunStageIsTenantIsolated(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	suffix := time.Now().UnixNano()
	ids := map[string]int64{}
	for _, name := range []string{"stage-a", "stage-b"} {
		var id int64
		if err := db.SQL().QueryRowContext(ctx,
			"INSERT INTO org (slug, name) VALUES ($1, $2) RETURNING id",
			name+"-"+itoa(suffix), name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids[name] = id
	}
	t.Cleanup(func() {
		_, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE id = ANY($1)",
			[]int64{ids["stage-a"], ids["stage-b"]})
	})

	for name, id := range ids {
		scoped, err := db.WithOrg(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
			var runPK int64
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO run (org_id, run_id, label) VALUES ($1, $2, $3) RETURNING id`,
				id, name+"-run", name).Scan(&runPK); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `
				INSERT INTO run_stage (run_pk, name, seq, status) VALUES ($1, 'subs', 0, 'succeeded')`, runPK)
			return err
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	for name, id := range ids {
		scoped, _ := db.WithOrg(ctx, id)
		var n int
		if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, "SELECT count(*) FROM run_stage").Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("tenant %s sees %d run stages, want exactly its own 1 (run_stage has no row-level security)", name, n)
		}
	}
}

// TestScopeSnapshotIsUniqueUnderConcurrency pins that runs with an identical scope
// share one snapshot even when they are recorded at the same moment. UpsertRun used
// to select and then insert with nothing to arbitrate, so concurrent runs each
// found no snapshot and each inserted one.
func TestScopeSnapshotIsUniqueUnderConcurrency(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	slug := "snap-" + itoa(time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })
	scoped, _ := db.WithOrg(ctx, orgID)

	const workers = 16
	errs := make(chan error, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func(i int) {
			<-start
			errs <- scoped.InTx(ctx, func(tx *sql.Tx) error {
				_, err := UpsertRun(ctx, tx, orgID,
					Run{RunID: "run-" + itoa(int64(i)), Label: "l", Mode: "domain", Status: "completed",
						Targets: []string{"t"}, Profile: "normal", StartedAt: time.Now()},
					Scope{AllowlistDigest: "same-digest", DenylistDigest: "same-deny"}, nil)
				return err
			})
		}(i)
	}
	close(start)
	for i := 0; i < workers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("a concurrent UpsertRun failed: %v", err)
		}
	}

	var n int
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, "SELECT count(*) FROM scope_snapshot").Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("scope snapshots = %d after %d concurrent runs with one scope, want 1", n, workers)
	}
}

// TestMigration0005MergesExistingDuplicateSnapshots pins the repair path: a database
// that already holds duplicate scope snapshots (made before the unique index
// existed) must come out with one snapshot per scope, every run still pointing at a
// snapshot that exists, and row-level security FORCEd again on the tables the
// migration had to lift it from.
func TestMigration0005MergesExistingDuplicateSnapshots(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Step back over 0005 (the newest migration is the one under test).
	ms, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if ms[len(ms)-1].Name != "scope_snapshot_unique" {
		t.Skipf("0005 is not the newest migration (it is %s); this test targets 0005", ms[len(ms)-1].Name)
	}
	if _, err := db.Rollback(ctx, 4); err != nil { // target version 4: reverts 0005 only
		t.Fatalf("Rollback 0005: %v", err)
	}

	slug := "merge-" + itoa(time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })
	scoped, _ := db.WithOrg(ctx, orgID)

	// Three identical snapshots, a fourth different one, and runs on two of the
	// duplicates plus one on the different one.
	var snaps [4]int64
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		for i := range snaps {
			digest := "dup"
			if i == 3 {
				digest = "different"
			}
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO scope_snapshot (org_id, allowlist_digest) VALUES ($1, $2) RETURNING id`,
				orgID, digest).Scan(&snaps[i]); err != nil {
				return err
			}
		}
		for i, snap := range []int64{snaps[1], snaps[2], snaps[3]} {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO run (org_id, run_id, label, scope_id) VALUES ($1, $2, 'l', $3)`,
				orgID, "mr-"+itoa(int64(i)), snap); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}

	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("re-applying 0005 over duplicates: %v", err)
	}

	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM scope_snapshot").Scan(&n); err != nil {
			return err
		}
		if n != 2 {
			t.Errorf("snapshots after the merge = %d, want 2 (one for the duplicated scope, one for the other)", n)
		}
		var dangling int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM run r
			WHERE r.scope_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM scope_snapshot s WHERE s.id = r.scope_id)`).
			Scan(&dangling); err != nil {
			return err
		}
		if dangling != 0 {
			t.Errorf("%d run(s) point at a snapshot that no longer exists", dangling)
		}
		var runs int
		if err := tx.QueryRowContext(ctx, "SELECT count(DISTINCT scope_id) FROM run").Scan(&runs); err != nil {
			return err
		}
		if runs != 2 {
			t.Errorf("runs reference %d distinct snapshots, want 2", runs)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The migration lifted FORCE to repair; it must be back on.
	for _, tbl := range []string{"run", "scope_snapshot"} {
		var forced bool
		if err := db.SQL().QueryRowContext(ctx,
			"SELECT relforcerowsecurity FROM pg_class WHERE relname = $1 AND relnamespace = 'public'::regnamespace",
			tbl).Scan(&forced); err != nil {
			t.Fatal(err)
		}
		if !forced {
			t.Errorf("%s no longer FORCEs row-level security after migration 0005", tbl)
		}
	}
}
