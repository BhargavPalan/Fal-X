package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// DiffRow is one entity that appeared or disappeared relative to a point in time.
type DiffRow struct {
	Kind       string
	Identifier string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// DiffFact is a new fact value observed on a pre-existing entity: a change, such as a
// new software version, a newly open port, or a new finding on a known host.
type DiffFact struct {
	Kind       string
	Identifier string
	Key        string
	Value      string
}

// Diff reports what changed since a point in time: entities first seen on or after
// `since` (added), entities not seen since before `since` (gone, i.e. last observed
// before the cutoff), and new fact values on entities that already existed (changed).
// A change report is a query over first_seen_at/last_seen_at, never a file comparison,
// so it is exact and reproducible. Row-level security scopes it to the tenant.
func Diff(ctx context.Context, tx *sql.Tx, since time.Time, limit int) (added, gone []DiffRow, changed []DiffFact, err error) {
	if limit <= 0 {
		limit = 200
	}
	added, err = diffRows(ctx, tx, `
		SELECT type, key, first_seen_at, last_seen_at FROM entity
		WHERE first_seen_at >= $1 ORDER BY first_seen_at DESC LIMIT $2`, since, limit)
	if err != nil {
		return nil, nil, nil, err
	}
	gone, err = diffRows(ctx, tx, `
		SELECT type, key, first_seen_at, last_seen_at FROM entity
		WHERE last_seen_at < $1 ORDER BY last_seen_at DESC LIMIT $2`, since, limit)
	if err != nil {
		return nil, nil, nil, err
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT e.type, e.key, f.key, f.value
		FROM entity_fact f JOIN entity e ON e.id = f.entity_id
		WHERE f.first_seen_at >= $1 AND e.first_seen_at < $1
		ORDER BY e.key, f.key LIMIT $2`, since, limit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("store: diff facts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var f DiffFact
		if err := rows.Scan(&f.Kind, &f.Identifier, &f.Key, &f.Value); err != nil {
			return nil, nil, nil, err
		}
		changed = append(changed, f)
	}
	return added, gone, changed, rows.Err()
}

// diffRows runs one of the entity diff queries.
func diffRows(ctx context.Context, tx *sql.Tx, query string, since time.Time, limit int) ([]DiffRow, error) {
	rows, err := tx.QueryContext(ctx, query, since, limit)
	if err != nil {
		return nil, fmt.Errorf("store: diff entities: %w", err)
	}
	defer rows.Close()
	var out []DiffRow
	for rows.Next() {
		var r DiffRow
		if err := rows.Scan(&r.Kind, &r.Identifier, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
