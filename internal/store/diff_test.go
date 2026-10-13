package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"
)

func TestDiffAddedGoneChanged(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	slug := fmt.Sprintf("diff-%d", time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })

	scoped, _ := db.WithOrg(ctx, orgID)
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		ins := func(typ, key string) (int64, error) {
			var id int64
			err := tx.QueryRowContext(ctx,
				"INSERT INTO entity (org_id, type, key, display) VALUES ($1,$2,$3,$3) RETURNING id", orgID, typ, key).Scan(&id)
			return id, err
		}
		// new.test: first_seen now -> added. old.test: first_seen 2h ago -> pre-existing.
		// gone.test: both timestamps 2h ago -> gone.
		if _, err := ins("host", "new.test"); err != nil {
			return err
		}
		oldID, err := ins("host", "old.test")
		if err != nil {
			return err
		}
		goneID, err := ins("host", "gone.test")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE entity SET first_seen_at = now() - interval '2 hours', last_seen_at = now() WHERE id = $1", oldID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE entity SET first_seen_at = now() - interval '2 hours', last_seen_at = now() - interval '2 hours' WHERE id = $1", goneID); err != nil {
			return err
		}
		// A new fact on the pre-existing entity -> a change.
		_, err = tx.ExecContext(ctx,
			"INSERT INTO entity_fact (entity_id, key, value, source) VALUES ($1,'server','nginx/1.25','test')", oldID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	cutoff := time.Now().Add(-1 * time.Hour)
	var added, gone []DiffRow
	var changed []DiffFact
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		added, gone, changed, err = Diff(ctx, tx, cutoff, 100)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	has := func(rows []DiffRow, key string) bool {
		for _, r := range rows {
			if r.Identifier == key {
				return true
			}
		}
		return false
	}
	if !has(added, "new.test") || has(added, "gone.test") || has(added, "old.test") {
		t.Errorf("added wrong: %+v", added)
	}
	if !has(gone, "gone.test") || has(gone, "new.test") {
		t.Errorf("gone wrong: %+v", gone)
	}
	gotChange := false
	for _, f := range changed {
		if f.Identifier == "old.test" && f.Key == "server" {
			gotChange = true
		}
	}
	if !gotChange {
		t.Errorf("expected a changed fact on old.test, got %+v", changed)
	}
}
