package store

import (
	"context"
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
	return db
}

// TestMigrateAppliesAndRollsBack is the phase 0 schema gate: every migration
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
	wantPolicies := 6
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT count(*) FROM pg_policies WHERE schemaname='public'").Scan(&policies); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if policies != wantPolicies {
		t.Errorf("row-level security policies: got %d, want %d", policies, wantPolicies)
	}

	// Every tenant-scoped table except org must have RLS switched on. A table
	// with no policy is silently readable by every tenant, which is the exact
	// failure this layer exists to prevent.
	for _, tbl := range []string{
		"app_user", "scope_snapshot", "run", "asset", "asset_attribute", "asset_observation",
	} {
		var enabled bool
		err := db.SQL().QueryRowContext(ctx,
			"SELECT relrowsecurity FROM pg_class WHERE relname = $1 AND relnamespace = 'public'::regnamespace",
			tbl).Scan(&enabled)
		if err != nil {
			t.Fatalf("check RLS on %s: %v", tbl, err)
		}
		if !enabled {
			t.Errorf("table %s has row-level security disabled", tbl)
		}
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
			if err := db.captureFingerprint(ctx); err != nil {
				t.Fatalf("capture fingerprint: %v", err)
			}

			restore := func() {
				t.Helper()
				for _, stmt := range tc.restore {
					if _, err := db.SQL().ExecContext(context.Background(), stmt); err != nil {
						t.Fatalf("restore %q: %v", stmt, err)
					}
				}
				if err := db.captureFingerprint(context.Background()); err != nil {
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
		_, err = scoped.SQL().ExecContext(ctx,
			"INSERT INTO asset (org_id, kind, identifier) VALUES ($1, 'host', $2)",
			id, name+".example.test")
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
		err = scoped.SQL().QueryRowContext(ctx,
			"SELECT count(*) FROM asset").Scan(&n)
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
