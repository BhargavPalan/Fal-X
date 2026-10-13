package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// Byte budgets for values that reach an indexed column. Postgres will not store
// U+0000 in a text column, and a btree index entry has to fit in 2704 bytes, so a
// value from a scanned host is clipped and marked before it is stored.
const (
	maxOrgSlug = 200
	maxText    = 4000
)

// dbText makes a value from a scanned host storable: invalid UTF-8 is replaced, a
// NUL becomes U+FFFD, and an over-long value is cut and marked so what was dropped
// stays visible. The result never exceeds limit.
//
// Every value that reaches a column must pass through here, because an import is one
// transaction and a single bad byte would otherwise roll back the whole run.
func dbText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "�")
	if len(s) <= limit {
		return s
	}
	marker := func(dropped int) string { return fmt.Sprintf("…[+%d bytes]", dropped) }
	cut := limit - len(marker(len(s)))
	if cut < 0 {
		cut = limit
		marker = func(int) string { return "" }
	}
	cut = max(cut, 0)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + marker(len(s)-cut)
}

// SafeText is dbText for callers outside this package that store text from an
// outside source, such as a vulnerability feed or a scanned host.
func SafeText(s string, limit int) string { return dbText(s, limit) }

// EnsureOrg returns the id of the organization with this slug, creating it when it
// does not exist. org is outside row-level security, because a session has to find
// its own org before it has an org id.
func (d *DB) EnsureOrg(ctx context.Context, slug, name string) (int64, error) {
	slug, name = dbText(slug, maxOrgSlug), dbText(name, maxText)
	var id int64
	err := d.sql.QueryRowContext(ctx, `
		INSERT INTO org (slug, name) VALUES ($1, $2)
		ON CONFLICT (slug) DO UPDATE SET slug = EXCLUDED.slug
		RETURNING id`, slug, name).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: ensure org %q: %w", slug, err)
	}
	return id, nil
}

// The functions below take the *sql.Tx InTx hands out, so every statement runs as
// the tenant the transaction was opened for. Row-level security is what scopes a
// read; an org id passed in would be a second, weaker opinion about who the caller
// is.

// AssetRow is one line of an inventory listing. Kind and Identifier are the
// entity's type and key.
type AssetRow struct {
	Kind       string
	Identifier string
	FirstSeen  time.Time
	LastSeen   time.Time
	Runs       int
}

// ListAssets returns the entity inventory, newest first, optionally of one type.
func ListAssets(ctx context.Context, tx *sql.Tx, kind string, limit int) ([]AssetRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT e.type, e.key, e.first_seen_at, e.last_seen_at,
		       (SELECT count(DISTINCT run_pk) FROM entity_fact f
		        WHERE f.entity_id = e.id AND f.run_pk IS NOT NULL)
		FROM entity e
		WHERE ($1 = '' OR e.type = $1)
		ORDER BY e.last_seen_at DESC, e.id DESC
		LIMIT $2`, kind, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list assets: %w", err)
	}
	defer rows.Close()
	var out []AssetRow
	for rows.Next() {
		var r AssetRow
		if err := rows.Scan(&r.Kind, &r.Identifier, &r.FirstSeen, &r.LastSeen, &r.Runs); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Attribute is one fact about an entity.
type Attribute struct {
	Key        string
	Value      string
	Source     string
	Confidence float64
	// SourceCount is how many distinct sources have asserted this fact; more than one
	// is corroboration.
	SourceCount int
	LastSeen    time.Time
}

// Corroborated is the confidence adjusted upward for corroboration: independent
// sources agreeing on a fact combine toward certainty (a saturating noisy-OR), so a
// value seen by several sources is trusted more than the same value from one.
func (a Attribute) Corroborated() float64 {
	return Corroborate(a.Confidence, a.SourceCount)
}

// Effective is the confidence after both corroboration and freshness decay: the value
// to actually reason with, higher when several sources agree and lower the longer it
// has been since the fact was last observed.
func (a Attribute) Effective() float64 {
	return Decay(a.Corroborated(), time.Since(a.LastSeen))
}

// Corroborate combines a base confidence over n independent observations:
// 1 - (1-base)^n, saturating toward 1. n below 1 is treated as 1.
func Corroborate(base float64, n int) float64 {
	if n < 1 {
		n = 1
	}
	c := 1 - math.Pow(1-base, float64(n))
	if c < 0 {
		return 0
	}
	if c > 1 {
		return 1
	}
	return c
}

// decayHalfLife is how long an unrefreshed observation takes to lose half its weight.
const decayHalfLife = 30 * 24 * time.Hour

// decayFloor keeps a stale observation weak evidence rather than no evidence.
const decayFloor = 0.1

// Decay reduces a confidence by how long ago it was last observed: an observation not
// refreshed decays on a half-life, so a fresh fact outweighs a stale one carried over
// from an old run. It never drops below a floor, since a stale observation is still a
// weak signal, not an absent one.
func Decay(base float64, age time.Duration) float64 {
	if age <= 0 {
		return base
	}
	f := math.Pow(0.5, age.Hours()/decayHalfLife.Hours())
	if f < decayFloor {
		f = decayFloor
	}
	return base * f
}

// AssetDetail is everything known about one entity.
type AssetDetail struct {
	AssetRow
	Criticality int
	Attributes  []Attribute
}

// GetAsset returns every entity matching a key (the same name can be a domain and a
// host at once), with its facts.
func GetAsset(ctx context.Context, tx *sql.Tx, identifier string) ([]AssetDetail, error) {
	type head struct {
		id int64
		d  AssetDetail
	}
	heads, err := func() ([]head, error) {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, type, key, first_seen_at, last_seen_at, criticality
			FROM entity WHERE key = $1 ORDER BY type`, identifier)
		if err != nil {
			return nil, fmt.Errorf("store: get asset: %w", err)
		}
		defer rows.Close()
		var out []head
		for rows.Next() {
			var h head
			if err := rows.Scan(&h.id, &h.d.Kind, &h.d.Identifier, &h.d.FirstSeen, &h.d.LastSeen, &h.d.Criticality); err != nil {
				return nil, err
			}
			out = append(out, h)
		}
		return out, rows.Err()
	}()
	if err != nil {
		return nil, err
	}

	out := make([]AssetDetail, 0, len(heads))
	for _, h := range heads {
		if h.d.Attributes, err = attributesOf(ctx, tx, h.id); err != nil {
			return nil, err
		}
		out = append(out, h.d)
	}
	return out, nil
}

// attributesOf returns every recorded fact about an entity.
func attributesOf(ctx context.Context, tx *sql.Tx, entityID int64) ([]Attribute, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT key, value, source, confidence, cardinality(sources), last_seen_at
		FROM entity_fact WHERE entity_id = $1 ORDER BY key, value`, entityID)
	if err != nil {
		return nil, fmt.Errorf("store: attributes: %w", err)
	}
	defer rows.Close()
	var out []Attribute
	for rows.Next() {
		var a Attribute
		if err := rows.Scan(&a.Key, &a.Value, &a.Source, &a.Confidence, &a.SourceCount, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// FindingRow is one stored finding with the entity it was found on. Findings are
// entity facts with the key "finding".
type FindingRow struct {
	Kind        string
	Identifier  string
	Criticality int
	Value       string
	Source      string
}

// ListFindings returns every finding recorded against the tenant's entities.
func ListFindings(ctx context.Context, tx *sql.Tx) ([]FindingRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT e.type, e.key, e.criticality, f.value, f.source
		FROM entity_fact f JOIN entity e ON e.id = f.entity_id
		WHERE f.key = 'finding'
		ORDER BY e.key, f.value`)
	if err != nil {
		return nil, fmt.Errorf("store: list findings: %w", err)
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var r FindingRow
		if err := rows.Scan(&r.Kind, &r.Identifier, &r.Criticality, &r.Value, &r.Source); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetCriticality records the operator's rating of an entity, 0 (unset) to 100, and
// returns how many entities it applied to. The same key can be several entities (a
// name that is both a domain and a host), and a rating describes the thing, not the
// type. Criticality comes only from the operator, never from inference.
func SetCriticality(ctx context.Context, tx *sql.Tx, identifier string, value int) (int64, error) {
	if value < 0 || value > 100 {
		return 0, fmt.Errorf("store: criticality %d is outside 0 to 100", value)
	}
	res, err := tx.ExecContext(ctx,
		"UPDATE entity SET criticality = $2 WHERE key = $1", identifier, value)
	if err != nil {
		return 0, fmt.Errorf("store: set criticality: %w", err)
	}
	return res.RowsAffected()
}
