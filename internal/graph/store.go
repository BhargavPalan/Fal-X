package graph

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/store"
)

// Byte budgets for values that reach an indexed column. entity.key and
// entity_fact.value sit in unique indexes, so they must fit a btree tuple; the
// others are bounded to keep a hostile banner from bloating a row. Every text
// value passes through store.SafeText, which also strips the NUL bytes Postgres
// refuses, so one bad value from a scanned host cannot roll back a whole commit.
const (
	maxKey    = 1800
	maxType   = 64
	maxValue  = 1800
	maxSource = 500
	maxText   = 4000
)

// FactEntity is an entity that carries a particular fact value, with when that fact
// was last observed, so correlation can weight a fresh shared value above a stale one.
type FactEntity struct {
	ID       int64
	Type     EntityType
	LastSeen time.Time
}

// EntitiesByFact groups the tenant's entities by the value of one fact key, for
// correlation: every entity sharing a value (a TLS fingerprint, a favicon hash) is a
// candidate sibling. Only values held by more than one entity are returned.
func EntitiesByFact(ctx context.Context, tx *sql.Tx, key string) (map[string][]FactEntity, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT f.value, e.id, e.type, f.last_seen_at
		FROM entity_fact f JOIN entity e ON e.id = f.entity_id
		WHERE f.key = $1
		ORDER BY f.value, e.id`, key)
	if err != nil {
		return nil, fmt.Errorf("graph: entities by fact %q: %w", key, err)
	}
	defer rows.Close()
	groups := map[string][]FactEntity{}
	for rows.Next() {
		var value string
		var fe FactEntity
		var typ string
		if err := rows.Scan(&value, &fe.ID, &typ, &fe.LastSeen); err != nil {
			return nil, err
		}
		fe.Type = EntityType(typ)
		groups[value] = append(groups[value], fe)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for value, ents := range groups {
		if len(ents) < 2 {
			delete(groups, value)
		}
	}
	return groups, nil
}

// InvRow is one entity with one of its facts, flattened for projection. An entity
// with no facts appears once with empty fact fields.
type InvRow struct {
	EntityType string
	EntityKey  string
	FactKey    string
	FactValue  string
	Source     string
	Confidence float64
}

// Inventory returns every entity with its facts, for projecting the graph into the
// asset inventory the matcher reads. Row-level security scopes it to the tenant.
func Inventory(ctx context.Context, tx *sql.Tx) ([]InvRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT e.type, e.key,
		       COALESCE(f.key, ''), COALESCE(f.value, ''),
		       COALESCE(f.source, ''), COALESCE(f.confidence, 1.0)
		FROM entity e
		LEFT JOIN entity_fact f ON f.entity_id = e.id
		ORDER BY e.type, e.key`)
	if err != nil {
		return nil, fmt.Errorf("graph: inventory: %w", err)
	}
	defer rows.Close()
	var out []InvRow
	for rows.Next() {
		var r InvRow
		if err := rows.Scan(&r.EntityType, &r.EntityKey, &r.FactKey, &r.FactValue, &r.Source, &r.Confidence); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountByType returns how many entities of each type the tenant has. Row-level
// security scopes it to the caller's organization.
func CountByType(ctx context.Context, tx *sql.Tx) (map[EntityType]int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT type, count(*) FROM entity GROUP BY type ORDER BY type`)
	if err != nil {
		return nil, fmt.Errorf("graph: count by type: %w", err)
	}
	defer rows.Close()
	out := map[EntityType]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[EntityType(t)] = n
	}
	return out, rows.Err()
}

// clamp keeps a confidence inside the [0,1] the column's CHECK constraint allows,
// so a caller's rounding error cannot roll back the transaction.
func clamp(c float64) float64 {
	if c < 0 {
		return 0
	}
	if c > 1 {
		return 1
	}
	return c
}

// Resolve upserts an entity and returns its ref. Seeing the same (type, key)
// again refreshes last_seen_at, fills a missing display, and keeps the smaller
// seed distance, so an entity reached by a shorter path is recorded as closer to
// the seed. The transaction must be opened for the organization.
func Resolve(ctx context.Context, tx *sql.Tx, orgID int64, t EntityType, key, display string, seedDistance int) (Ref, error) {
	k := store.SafeText(key, maxKey)
	if k == "" {
		return 0, fmt.Errorf("graph: empty key for entity type %q", t)
	}
	typ := store.SafeText(string(t), maxType)
	disp := store.SafeText(display, maxText)
	var id int64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO entity (org_id, type, key, display, seed_distance)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (org_id, type, key) DO UPDATE SET
			last_seen_at = now(),
			display = COALESCE(NULLIF(entity.display, ''), EXCLUDED.display),
			seed_distance = LEAST(entity.seed_distance, EXCLUDED.seed_distance)
		RETURNING id`,
		orgID, typ, k, disp, seedDistance).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("graph: resolve %s %q: %w", t, key, err)
	}
	return Ref(id), nil
}

// AddEdge records a typed relationship. It refuses a pairing the taxonomy does not
// allow, because a mis-typed edge is a programming error, not data. Seeing the same
// edge again refreshes last_seen_at and raises its confidence toward the higher
// observation, which is how corroboration strengthens an edge rather than
// overwriting it.
func AddEdge(ctx context.Context, tx *sql.Tx, orgID int64, src, dst Ref, rel EdgeType, srcType, dstType EntityType, confidence float64) error {
	if !ValidRelationship(rel, srcType, dstType) {
		return fmt.Errorf("graph: %s is not a valid relationship from %s to %s", rel, srcType, dstType)
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO entity_edge (org_id, src_id, dst_id, rel, confidence, inferred)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (org_id, src_id, dst_id, rel) DO UPDATE SET
			last_seen_at = now(),
			confidence = GREATEST(entity_edge.confidence, EXCLUDED.confidence)`,
		orgID, int64(src), int64(dst), store.SafeText(string(rel), maxType), clamp(confidence), Inferred(rel))
	if err != nil {
		return fmt.Errorf("graph: edge %s %d->%d: %w", rel, src, dst, err)
	}
	return nil
}

// AddFact records an observed property of an entity, keyed by (entity, key, value)
// so the same observation is not duplicated. Seeing it again refreshes
// last_seen_at and raises confidence. runPK of zero records no run.
func AddFact(ctx context.Context, tx *sql.Tx, on Ref, key, value, source string, passive bool, confidence float64, runPK int64) error {
	k := store.SafeText(key, maxSource)
	v := store.SafeText(value, maxValue)
	if k == "" || v == "" {
		// An empty key or value would be a useless row and cannot form a key.
		return nil
	}
	var run any
	if runPK != 0 {
		run = runPK
	}
	// sources accumulates the distinct set of sources that have asserted this exact
	// fact; confidence keeps the strongest single observation, and the corroboration
	// (a function of the set size) is derived by readers. The merge is a distinct union,
	// so re-running the same source does not inflate anything.
	_, err := tx.ExecContext(ctx, `
		INSERT INTO entity_fact (entity_id, key, value, source, sources, passive, confidence, run_pk)
		VALUES ($1, $2, $3, $4, CASE WHEN $4 = '' THEN '{}'::text[] ELSE ARRAY[$4] END, $5, $6, $7)
		ON CONFLICT (entity_id, key, value) DO UPDATE SET
			last_seen_at = now(),
			source = EXCLUDED.source,
			sources = (SELECT array_agg(DISTINCT s ORDER BY s)
			           FROM unnest(entity_fact.sources || EXCLUDED.sources) AS s),
			confidence = GREATEST(entity_fact.confidence, EXCLUDED.confidence)`,
		int64(on), k, v, store.SafeText(source, maxSource), passive, clamp(confidence), run)
	if err != nil {
		return fmt.Errorf("graph: fact %s on %d: %w", key, on, err)
	}
	return nil
}
