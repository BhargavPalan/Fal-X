package attackpath

import (
	"context"
	"database/sql"
	"fmt"
)

// Load builds the attack graph from the entity graph in the caller's transaction, so
// row-level security scopes it to the tenant. A technology edge is skipped: two
// services sharing a technology node are not an attacker pivot, only a coincidence.
func Load(ctx context.Context, tx *sql.Tx) (*Graph, error) {
	g := NewGraph()

	nodes, err := tx.QueryContext(ctx, `SELECT id, type, key, seed_distance, criticality FROM entity`)
	if err != nil {
		return nil, fmt.Errorf("attackpath: load entities: %w", err)
	}
	defer nodes.Close()
	for nodes.Next() {
		var n Node
		if err := nodes.Scan(&n.ID, &n.Type, &n.Key, &n.SeedDistance, &n.Criticality); err != nil {
			return nil, err
		}
		g.AddNode(&n)
	}
	if err := nodes.Err(); err != nil {
		return nil, err
	}

	exp, err := tx.QueryContext(ctx, `SELECT entity_id, value FROM entity_fact WHERE key = 'exposure'`)
	if err != nil {
		return nil, fmt.Errorf("attackpath: load exposures: %w", err)
	}
	defer exp.Close()
	for exp.Next() {
		var id int64
		var value string
		if err := exp.Scan(&id, &value); err != nil {
			return nil, err
		}
		if n := g.Nodes[id]; n != nil {
			n.Exposures = append(n.Exposures, value)
		}
	}
	if err := exp.Err(); err != nil {
		return nil, err
	}

	edges, err := tx.QueryContext(ctx, `
		SELECT src_id, dst_id, rel, confidence FROM entity_edge WHERE rel <> 'runs_tech'`)
	if err != nil {
		return nil, fmt.Errorf("attackpath: load edges: %w", err)
	}
	defer edges.Close()
	for edges.Next() {
		var src, dst int64
		var rel string
		var conf float64
		if err := edges.Scan(&src, &dst, &rel, &conf); err != nil {
			return nil, err
		}
		// Only connect nodes that both exist in this tenant's graph.
		if g.Nodes[src] != nil && g.Nodes[dst] != nil {
			g.AddEdge(src, dst, rel, conf)
		}
	}
	return g, edges.Err()
}
