package graph

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/store"
	"github.com/BhargavPalan/Fal-X/internal/storetest"
)

func TestAddFactMergesDistinctSources(t *testing.T) {
	db := storetest.NewTestDB(t)
	ctx := context.Background()
	slug := fmt.Sprintf("corrob-%d", time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })

	scoped, _ := db.WithOrg(ctx, orgID)
	var count int
	var conf float64
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		ref, err := Resolve(ctx, tx, orgID, TypeHost, "x.test", "x.test", 0)
		if err != nil {
			return err
		}
		// The same fact from two sources, then a repeat of the first (idempotent).
		for _, s := range []struct {
			src  string
			conf float64
		}{{"ct", 0.6}, {"passive-dns", 0.5}, {"ct", 0.6}} {
			if err := AddFact(ctx, tx, ref, "tech", "nginx", s.src, true, s.conf, 0); err != nil {
				return err
			}
		}
		return tx.QueryRowContext(ctx,
			"SELECT cardinality(sources), confidence FROM entity_fact WHERE entity_id = $1 AND key = 'tech' AND value = 'nginx'",
			int64(ref)).Scan(&count, &conf)
	}); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("distinct sources = %d, want 2 (ct, passive-dns; the ct repeat must not grow it)", count)
	}
	// The confidence column is a 32-bit real, so compare within float precision.
	if conf < 0.59 || conf > 0.61 {
		t.Errorf("stored confidence = %v, want the strongest single observation ~0.6", conf)
	}
	if got := store.Corroborate(conf, count); got <= conf {
		t.Errorf("corroborated confidence %v should exceed the single-source base %v", got, conf)
	}
}
