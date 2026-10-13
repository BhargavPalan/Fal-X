package engine

import (
	"context"
	"database/sql"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// DBCommitter writes a buffer to the graph in one transaction as the tenant. The
// whole buffer commits or nothing does, so a source's emissions never reach the
// graph half-written.
type DBCommitter struct {
	DB    *store.DB // already bound to the organization via WithOrg
	OrgID int64
	RunPK int64 // 0 when the run is not persisted to a run row
}

// NewDBCommitter returns a committer for an org-bound store handle.
func NewDBCommitter(db *store.DB, orgID, runPK int64) *DBCommitter {
	return &DBCommitter{DB: db, OrgID: orgID, RunPK: runPK}
}

// Commit resolves every buffered entity to a real id, then writes the facts and
// edges against those ids, all in one transaction. It returns the distinct
// entities produced so the engine can enqueue them.
func (c *DBCommitter) Commit(ctx context.Context, b *Buffer, source string, passive bool, seedDistance int) ([]Produced, error) {
	local := make([]graph.Ref, len(b.entities))
	err := c.DB.InTx(ctx, func(tx *sql.Tx) error {
		for i, e := range b.entities {
			ref, err := graph.Resolve(ctx, tx, c.OrgID, e.t, e.key, e.display, seedDistance)
			if err != nil {
				return err
			}
			local[i] = ref
		}
		for _, f := range b.facts {
			on, ok := realRef(local, f.on)
			if !ok {
				continue
			}
			if err := graph.AddFact(ctx, tx, on, f.key, f.value, source, passive, f.confidence, c.RunPK); err != nil {
				return err
			}
		}
		for _, ed := range b.edges {
			se, ok1 := b.entityAt(ed.from)
			de, ok2 := b.entityAt(ed.to)
			if !ok1 || !ok2 {
				continue
			}
			if !graph.ValidRelationship(ed.rel, se.t, de.t) {
				// A source emitted an edge the taxonomy forbids. Drop it rather than
				// abort the whole source's commit, and record it so the source can be
				// fixed.
				logging.Warn("engine: dropping invalid edge %s from %s to %s", ed.rel, se.t, de.t)
				continue
			}
			from, ok1 := realRef(local, ed.from)
			to, ok2 := realRef(local, ed.to)
			if !ok1 || !ok2 {
				continue
			}
			if err := graph.AddEdge(ctx, tx, c.OrgID, from, to, ed.rel, se.t, de.t, ed.confidence); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	produced := make([]Produced, 0, len(b.entities))
	for _, e := range b.entities {
		produced = append(produced, Produced{Type: e.t, Key: e.key})
	}
	return produced, nil
}

// realRef maps a buffer handle to the resolved database id.
func realRef(local []graph.Ref, ref graph.Ref) (graph.Ref, bool) {
	i := int(ref) - 1
	if i < 0 || i >= len(local) {
		return 0, false
	}
	return local[i], true
}
