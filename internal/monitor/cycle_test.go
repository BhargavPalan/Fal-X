package monitor

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

func TestCycleReportsNewAssetAndChangeThenDedupes(t *testing.T) {
	db := storetest.NewTestDB(t)
	ctx := context.Background()
	slug := fmt.Sprintf("monitor-%d", time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })
	scoped, _ := db.WithOrg(ctx, orgID)

	// An old host (backdated so it is not "added") that just grew a new finding, and a
	// brand-new host that is itself an addition.
	var oldID int64
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		old, err := graph.Resolve(ctx, tx, orgID, graph.TypeHost, "known.example.com", "known.example.com", 0)
		if err != nil {
			return err
		}
		oldID = int64(old)
		if _, err := tx.ExecContext(ctx,
			"UPDATE entity SET first_seen_at = now() - interval '2 days' WHERE id = $1", oldID); err != nil {
			return err
		}
		if err := graph.AddFact(ctx, tx, old, "finding", "high exposed-git-repository", "native/exposedfiles", false, 0.8, 0); err != nil {
			return err
		}
		_, err = graph.Resolve(ctx, tx, orgID, graph.TypeHost, "fresh.example.com", "fresh.example.com", 1)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	since := time.Now().Add(-1 * time.Hour)
	events, err := Cycle(ctx, scoped, since, 500)
	if err != nil {
		t.Fatal(err)
	}

	var gotAdded, gotChanged bool
	for _, e := range events {
		if e.Type == "added" && e.Key == "fresh.example.com" {
			gotAdded = true
		}
		if e.Type == "changed" && e.Key == "known.example.com" && strings.Contains(e.Detail, "exposed-git-repository") {
			if e.Severity != "high" {
				t.Errorf("new finding severity = %q, want high", e.Severity)
			}
			gotChanged = true
		}
	}
	if !gotAdded {
		t.Errorf("expected an 'added' event for fresh.example.com, got %+v", events)
	}
	if !gotChanged {
		t.Errorf("expected a 'changed' finding event for known.example.com, got %+v", events)
	}

	// A cycle whose cutoff is after the changes reports nothing: the window bounded by
	// `since` moves forward each cycle, so every change falls in exactly one window.
	later, err := scoped.Now(ctx)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Cycle(ctx, scoped, later, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Errorf("a later cutoff must report nothing new, got %d: %+v", len(again), again)
	}
}
