package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// auditOrg creates a tenant to test in and removes it afterwards.
func auditOrg(t *testing.T, db *DB, slug string) int64 {
	t.Helper()
	ctx := context.Background()
	slug = slug + "-" + itoa(time.Now().UnixNano())
	var id int64
	err := db.SQL().QueryRowContext(ctx,
		"INSERT INTO org (slug, name) VALUES ($1, $2) RETURNING id", slug, slug).Scan(&id)
	if err != nil {
		t.Fatalf("insert org %s: %v", slug, err)
	}
	t.Cleanup(func() {
		_, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE id = $1", id)
	})
	return id
}

// auditCount counts the rows of one table inside a tenant scope.
func auditCount(t *testing.T, db *DB, orgID int64, table string) int {
	t.Helper()
	scoped, err := db.WithOrg(context.Background(), orgID)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	err = scoped.InTx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(),
			"SELECT count(*) FROM "+table).Scan(&n)
	})
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// Page titles, banners and URLs are chosen by the scanned host. Postgres will not
// store U+0000 in a text column and a btree index entry has to fit in 2704 bytes,
// so a hostile or broken host can hand the importer a value that Postgres rejects.
// Before this was handled, one such value rolled back the import of the whole run,
// losing every other asset it contained.
func TestHostileValuesDoNotAbortAnImport(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	orgID := auditOrg(t, db, "audit-hostile")
	scoped, err := db.WithOrg(ctx, orgID)
	if err != nil {
		t.Fatal(err)
	}

	hostile := []struct {
		name       string
		kind       string
		identifier string
		key        string
		value      string
	}{
		{"nul in title", "url", "http://a.test/1", "title", "before\x00after"},
		{"nul in url", "url", "http://a.test/\x00x", "title", "t"},
		{"nul only", "host", "\x00", "title", "v"},
		{"oversized title", "url", "http://a.test/2", "title", strings.Repeat("L", 500000)},
		{"oversized identifier", "url", "http://a.test/" + strings.Repeat("U", 100000), "title", "v"},
		{"invalid utf8", "url", "http://a.test/3", "title", "X\xff\xfeY"},
		{"control chars", "url", "http://a.test/4", "title", "A\x01\x02\x1b[31mB"},
		{"nul in key", "url", "http://a.test/5", "ti\x00tle", "v"},
		{"oversized key", "url", "http://a.test/6", strings.Repeat("K", 10000), "v"},
		{"quote attempt", "url", "http://a.test/7';--", "title", "'; DROP TABLE asset; --"},
	}

	err = scoped.InTx(ctx, func(tx *sql.Tx) error {
		runPK, err := UpsertRun(ctx, tx, orgID,
			Run{RunID: "hostile-run\x00id", Label: "l\x00b", Mode: "domain",
				Status: "completed", Targets: []string{"t\x00", "ok.test"}},
			Scope{AllowlistDigest: "d\x00ig"},
			[]Stage{{Name: "s\x00t", Status: "succeeded", Note: strings.Repeat("N", 9000)}})
		if err != nil {
			return err
		}
		for _, h := range hostile {
			id, err := UpsertAsset(ctx, tx, orgID, h.kind, h.identifier)
			if err != nil {
				return err
			}
			if err := AddAttribute(ctx, tx, id, h.key, h.value, "src\x00", 1); err != nil {
				return err
			}
			if err := Observe(ctx, tx, id, runPK, "st\x00age"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("a hostile value aborted the whole import: %v", err)
	}

	// Every asset must be present, and the rest of the run intact.
	if n := auditCount(t, db, orgID, "asset"); n != len(hostile) {
		t.Errorf("asset rows = %d, want %d: a hostile value lost the others", n, len(hostile))
	}
	if n := auditCount(t, db, orgID, "run"); n != 1 {
		t.Errorf("run rows = %d, want 1", n)
	}
	if n := auditCount(t, db, orgID, "run_stage"); n != 1 {
		t.Errorf("run_stage rows = %d, want 1", n)
	}
}

// Truncation must be visible. A title quietly shortened into something that looks
// ordinary would hide evidence in a tool whose whole purpose is evidence. The
// marker must also fit inside the budget, at every budget the store uses.
func TestTruncationIsAnnounced(t *testing.T) {
	budgets := map[string]int{
		"attrValue": maxAttrValue, "attrKey": maxAttrKey, "assetID": maxAssetID,
		"runID": maxRunID, "label": maxLabel, "stageName": maxStageName,
		"stageNote": maxStageNote, "orgSlug": maxOrgSlug, "text": maxText,
	}
	huge := []string{
		strings.Repeat("L", 500000),
		strings.Repeat("日", 5000),
		strings.Repeat("🔐", 3000),
		strings.Repeat("a", 10000),
	}
	for name, max := range budgets {
		for _, in := range huge {
			got := dbText(in, max)
			if len(got) > max {
				t.Errorf("%s: dbText returned %d bytes, over the %d budget (input %d bytes)",
					name, len(got), max, len(in))
			}
			if !utf8.ValidString(got) {
				t.Errorf("%s: dbText produced invalid UTF-8", name)
			}
			if !strings.Contains(got, "bytes]") {
				t.Errorf("%s: an over-long value was shortened without saying so: %q",
					name, got)
			}
		}
	}
}

// A value inside the budget must come back untouched, or every normal import
// would accumulate truncation markers.
func TestValuesWithinBudgetAreUnchanged(t *testing.T) {
	for _, s := range []string{
		"", "nginx", "http://example.com/path?q=1", "Apache/2.4.41 (Ubuntu)",
		strings.Repeat("a", 100), "日本語のタイトル", "emoji 🔐 title",
	} {
		if got := dbText(s, maxAttrValue); got != s {
			t.Errorf("dbText(%q) = %q, want it unchanged", s, got)
		}
	}
}

// Postgres forbids U+0000 outright, so it must be gone from anything stored.
func TestNulAndInvalidUTF8AreRemoved(t *testing.T) {
	if got := dbText("a\x00b", maxAttrValue); strings.ContainsRune(got, 0) {
		t.Errorf("dbText kept a NUL: %q", got)
	}
	if got := dbText("a\xffb", maxAttrValue); strings.Contains(got, "\xff") {
		t.Errorf("dbText kept an invalid byte: %q", got)
	}
}

// Truncation must not split a multi-byte rune, which would produce invalid UTF-8
// and be rejected by Postgres all the same.
func TestTruncationKeepsValidUTF8(t *testing.T) {
	for _, s := range []string{
		strings.Repeat("日", 5000),
		strings.Repeat("🔐", 3000),
		strings.Repeat("é", 8000),
	} {
		got := dbText(s, maxAttrValue)
		if !utf8.ValidString(got) {
			t.Errorf("dbText produced invalid UTF-8 (len %d) for %q", len(got), s[:8])
		}
	}
}

func TestDBTextNeverExceedsAnyBudget(t *testing.T) {
	long := strings.Repeat("é", 5000)
	for limit := 0; limit <= 120; limit++ {
		got := dbText(long, limit)
		if len(got) > limit {
			t.Fatalf("limit %d: got %d bytes", limit, len(got))
		}
		if !utf8.ValidString(got) {
			t.Fatalf("limit %d: invalid UTF-8", limit)
		}
	}
}
