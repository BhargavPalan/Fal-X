package store

import (
	"context"
	"database/sql"
	"fmt"
)

// Evidence is one observed fact about an entity that names software: a technology
// the probe detected or a server banner. AssetID holds the entity id.
type Evidence struct {
	AssetID    int64
	Kind       string // entity type
	Identifier string // entity key
	Key        string // fact key
	Value      string // fact value
}

// ListEvidence returns the software-naming facts of the tenant's entities.
func ListEvidence(ctx context.Context, tx *sql.Tx) ([]Evidence, error) {
	// The org_id predicate is defence in depth: row-level security already scopes this,
	// but an explicit filter also holds if the connection role were to bypass RLS.
	rows, err := tx.QueryContext(ctx, `
		SELECT e.id, e.type, e.key, f.key, f.value
		FROM entity_fact f JOIN entity e ON e.id = f.entity_id
		WHERE f.key IN ('tech', 'server', 'service') AND e.org_id = current_org_id()
		ORDER BY e.id, f.key, f.value`)
	if err != nil {
		return nil, fmt.Errorf("store: list evidence: %w", err)
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		var e Evidence
		if err := rows.Scan(&e.AssetID, &e.Kind, &e.Identifier, &e.Key, &e.Value); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// MatchRow is one entity-to-CVE match. AssetID holds the entity id.
type MatchRow struct {
	AssetID    int64
	Evidence   string
	Software   string
	Version    string
	Vendor     string
	Product    string
	CVE        string
	Tier       string
	Confidence string
	Reason     string
	Conditions string
	Caveat     string
}

const (
	maxMatchField = 1000
	matchBatch    = 2000
)

// ReplaceMatches replaces the organization's matches with rows, in one statement
// per batch inside the caller's transaction, so readers never see the set half
// replaced.
func ReplaceMatches(ctx context.Context, tx *sql.Tx, orgID int64, rows []MatchRow) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM match_result WHERE org_id = $1", orgID); err != nil {
		return fmt.Errorf("store: clear matches: %w", err)
	}
	for start := 0; start < len(rows); start += matchBatch {
		batch := rows[start:min(start+matchBatch, len(rows))]
		var entity []int64
		var evidence, software, version, vendor, product, cve, tier, conf, reason, conds, caveat []string
		for _, r := range batch {
			entity = append(entity, r.AssetID)
			evidence = append(evidence, dbText(r.Evidence, maxMatchField))
			software = append(software, dbText(r.Software, maxMatchField))
			version = append(version, dbText(r.Version, maxMatchField))
			vendor = append(vendor, dbText(r.Vendor, maxMatchField))
			product = append(product, dbText(r.Product, maxMatchField))
			cve = append(cve, r.CVE)
			tier = append(tier, r.Tier)
			conf = append(conf, r.Confidence)
			reason = append(reason, dbText(r.Reason, maxText))
			conds = append(conds, dbText(r.Conditions, maxText))
			caveat = append(caveat, dbText(r.Caveat, maxText))
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO match_result
				(org_id, entity_id, evidence, software, version, vendor, product, cve_id,
				 tier, confidence, reason, conditions, caveat)
			SELECT $1, t.* FROM unnest($2::bigint[], $3::text[], $4::text[], $5::text[], $6::text[],
			       $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[]) AS t
			ON CONFLICT DO NOTHING`,
			orgID, entity, evidence, software, version, vendor, product, cve, tier, conf,
			reason, conds, caveat); err != nil {
			return fmt.Errorf("store: store matches: %w", err)
		}
	}
	return nil
}

// MatchedRow is a stored match with the entity it is on, for ranking. Kind and
// Identifier are the entity's type and key.
type MatchedRow struct {
	Kind        string
	Identifier  string
	Criticality int
	Software    string
	Version     string
	CVE         string
	Tier        string
	Confidence  string
	Reason      string
}

// ListMatched returns every stored match of the tenant with its entity.
func ListMatched(ctx context.Context, tx *sql.Tx) ([]MatchedRow, error) {
	// The org_id predicate is defence in depth, as in ListEvidence.
	rows, err := tx.QueryContext(ctx, `
		SELECT e.type, e.key, e.criticality, m.software, m.version, m.cve_id,
		       m.tier, m.confidence, m.reason
		FROM match_result m JOIN entity e ON e.id = m.entity_id
		WHERE m.org_id = current_org_id()
		ORDER BY e.key, m.cve_id`)
	if err != nil {
		return nil, fmt.Errorf("store: list matches: %w", err)
	}
	defer rows.Close()
	var out []MatchedRow
	for rows.Next() {
		var r MatchedRow
		if err := rows.Scan(&r.Kind, &r.Identifier, &r.Criticality, &r.Software, &r.Version,
			&r.CVE, &r.Tier, &r.Confidence, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
