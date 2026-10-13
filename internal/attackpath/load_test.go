package attackpath

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/storetest"
)

func TestLoadAndAnalyze(t *testing.T) {
	db := storetest.NewTestDB(t)
	ctx := context.Background()
	slug := fmt.Sprintf("ap-%d", time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })

	scoped, _ := db.WithOrg(ctx, orgID)
	var paths []Path
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		// seed host (distance 0) -> ip -> bucket (jewel), with an exposure on the bucket.
		h, err := graph.Resolve(ctx, tx, orgID, graph.TypeHost, "seed.test", "seed.test", 0)
		if err != nil {
			return err
		}
		ip, err := graph.Resolve(ctx, tx, orgID, graph.TypeIP, "192.0.2.1", "192.0.2.1", 1)
		if err != nil {
			return err
		}
		b, err := graph.Resolve(ctx, tx, orgID, graph.TypeBucket, "aws-s3:data", "aws-s3:data", 2)
		if err != nil {
			return err
		}
		if err := graph.AddEdge(ctx, tx, orgID, h, ip, graph.RelResolvesTo, graph.TypeHost, graph.TypeIP, 1); err != nil {
			return err
		}
		if err := graph.AddEdge(ctx, tx, orgID, ip, b, graph.RelSiblingOf, graph.TypeIP, graph.TypeBucket, 0.6); err != nil {
			return err
		}
		if err := graph.AddFact(ctx, tx, b, "exposure", "open_bucket", "test", true, 0.8, 0); err != nil {
			return err
		}
		g, err := Load(ctx, tx)
		if err != nil {
			return err
		}
		paths = Analyze(g)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if len(paths) == 0 {
		t.Fatal("expected at least one attack path from the seed to the bucket")
	}
	end := paths[0].Hops[len(paths[0].Hops)-1]
	if end.Key != "aws-s3:data" {
		t.Errorf("path target = %q, want the bucket aws-s3:data", end.Key)
	}
}
