package correlate

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/storetest"
)

func TestRarityWeighting(t *testing.T) {
	if r := rarity(2); r != 1.0 {
		t.Errorf("rarity(2) = %v, want 1.0 (a pair is maximally distinctive)", r)
	}
	// Weight must fall monotonically as the sharing group grows.
	prev := rarity(2)
	for _, g := range []int{3, 10, 50, 150, 199} {
		got := rarity(g)
		if got > prev {
			t.Errorf("rarity not monotonic: rarity(%d)=%v > previous %v", g, got, prev)
		}
		if got <= 0 || got > 1 {
			t.Errorf("rarity(%d)=%v out of (0,1]", g, got)
		}
		prev = got
	}
}

func TestUnionFindTransitive(t *testing.T) {
	u := newUnionFind()
	u.union(1, 2)
	u.union(2, 3)
	u.union(5, 6)
	if u.find(1) != u.find(3) {
		t.Error("1 and 3 should be unioned transitively through 2")
	}
	if u.find(1) == u.find(5) {
		t.Error("1 and 5 are in separate components")
	}
}

func TestCorrelateTransitiveClustering(t *testing.T) {
	db := storetest.NewTestDB(t)
	ctx := context.Background()
	slug := fmt.Sprintf("corr-%d", time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })

	scoped, _ := db.WithOrg(ctx, orgID)
	var idA, idB, idC int64
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		mk := func(name string, facts map[string]string) (int64, error) {
			ref, err := graph.Resolve(ctx, tx, orgID, graph.TypeHost, name, name, 0)
			if err != nil {
				return 0, err
			}
			for k, v := range facts {
				if err := graph.AddFact(ctx, tx, ref, k, v, "test", true, 1, 0); err != nil {
					return 0, err
				}
			}
			return int64(ref), nil
		}
		// A—B share a cert; B—C share a JARM: all three must end up in one cluster.
		if idA, err = mk("a.test", map[string]string{"tls_sha256": "cert1"}); err != nil {
			return err
		}
		if idB, err = mk("b.test", map[string]string{"tls_sha256": "cert1", "jarm": "jarm1"}); err != nil {
			return err
		}
		idC, err = mk("c.test", map[string]string{"jarm": "jarm1"})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := Run(ctx, scoped, orgID); err != nil {
		t.Fatal(err)
	}

	// Collect the component reachable through sibling_of edges and confirm A, B, C are
	// all connected.
	linked := map[int64]bool{}
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT src_id, dst_id FROM entity_edge WHERE rel = 'sibling_of'")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s, d int64
			if err := rows.Scan(&s, &d); err != nil {
				return err
			}
			linked[s], linked[d] = true, true
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if !linked[idA] || !linked[idB] || !linked[idC] {
		t.Errorf("A, B, C should all be clustered via transitive cert+jarm pivots; linked=%v (A=%d B=%d C=%d)", linked, idA, idB, idC)
	}
}
