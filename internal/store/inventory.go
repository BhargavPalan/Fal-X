package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Byte budgets for the values that reach an indexed column.
//
// Postgres will not store U+0000 in a text column at all, and a btree index entry
// has to fit in 2704 bytes. Page titles, banners and URLs all come from scanned
// hosts, so a hostile or merely broken host can produce a value that Postgres
// rejects, and one such value would otherwise roll back the import of an entire
// run. The budgets leave room for the other columns in each index tuple.
const (
	maxAttrValue = 1800 // asset_attribute (asset_id, key, value)
	maxAttrKey   = 200
	maxAssetID   = 1800 // asset (org_id, kind, identifier)
	maxRunID     = 400  // run (org_id, run_id)
	maxLabel     = 500
	maxStageName = 200
	maxStageNote = 2000
	maxOrgSlug   = 200
	maxText      = 4000 // unindexed text columns
)

// dbText makes a value from a scanned host storable.
//
// Invalid UTF-8 is replaced and a NUL becomes U+FFFD, because Postgres refuses
// both. An over-long value is cut and marked, so that what was dropped stays
// visible: a title that was 500,000 bytes long says so, rather than being quietly
// shortened into something that looks ordinary. The result never exceeds limit,
// even including the marker.
//
// Every value that reaches a column must pass through here. Page titles, banners
// and URLs are chosen by the scanned host, and an import is one transaction, so a
// single NUL byte or over-long value in one of them would otherwise roll back the
// whole run and lose every other asset in it. A new write path that forgets this
// reintroduces that failure, so it should call dbText even when the value looks
// operator-supplied.
//
// The lookup paths (GetAsset, SetCriticality, ListAssets) do not call this. Their
// arguments arrive as command-line values, and no mainstream system puts a NUL in
// argv, so the case cannot be reached; the value they match was stored through
// this function, so it is already storable.
func dbText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "�")
	if len(s) <= limit {
		return s
	}

	// The marker names the full length, which has at least as many digits as the
	// dropped length, so the result cannot exceed limit.
	marker := func(dropped int) string { return fmt.Sprintf("…[+%d bytes]", dropped) }
	cut := limit - len(marker(len(s)))
	if cut < 0 {
		// The budget cannot hold a marker: a plain cut is all that fits.
		cut = limit
		marker = func(int) string { return "" }
	}
	cut = max(cut, 0)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + marker(len(s)-cut)
}

// dbTexts applies dbText across a slice, dropping anything that sanitising left
// empty so it cannot become an empty unique key.
func dbTexts(in []string, limit int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if v := dbText(s, limit); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// The functions here take the *sql.Tx InTx hands out, so every statement runs as
// the tenant the transaction was opened for. None of them accept an org id for
// reads: row-level security is what scopes a read, and an id passed in would be
// a second, weaker opinion about who the caller is.

// Run is one scan as the database records it.
type Run struct {
	RunID        string
	Label        string
	Mode         string
	Status       string
	Targets      []string
	Profile      string
	ToolVersions string // JSON object
	StartedAt    time.Time
	FinishedAt   *time.Time
	DurationSecs int
}

// Stage is one run stage as the database records it.
type Stage struct {
	Name         string
	Seq          int
	Status       string
	ExitCode     int
	DurationSecs int
	Inputs       int64
	Outputs      int64
	Note         string
}

// Scope is the authorization a run was held to.
type Scope struct {
	AllowlistDigest string
	DenylistDigest  string
	AllowPrivate    bool
	AllowAny        bool
}

// EnsureOrg returns the id of the organization with this slug, creating it when
// it does not exist.
//
// org is deliberately outside row-level security, because a session has to find
// its own org before it has an org id, so this works on the plain pool.
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

// UpsertRun records a run, its scope and its stages, and returns the run's key.
//
// It is idempotent: importing the same run twice updates it in place instead of
// duplicating it, which is what lets `assets import` be re-run safely.
func UpsertRun(ctx context.Context, tx *sql.Tx, orgID int64, r Run, sc Scope, stages []Stage) (int64, error) {
	r.RunID = dbText(r.RunID, maxRunID)
	r.Label = dbText(r.Label, maxLabel)
	r.Profile = dbText(r.Profile, maxText)
	r.Targets = dbTexts(r.Targets, maxLabel)
	sc.AllowlistDigest = dbText(sc.AllowlistDigest, maxText)
	sc.DenylistDigest = dbText(sc.DenylistDigest, maxText)
	// One statement, arbitrated by the unique index scope_snapshot_identity_idx:
	// concurrent runs with the same scope all get the same snapshot. The no-op
	// UPDATE is what lets RETURNING give back the existing row's id.
	var scopeID int64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO scope_snapshot
			(org_id, allowlist_digest, denylist_digest, allow_private, allow_any)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5)
		ON CONFLICT (org_id, allowlist_digest, (COALESCE(denylist_digest, '')), allow_private, allow_any)
		DO UPDATE SET created_at = scope_snapshot.created_at
		RETURNING id`,
		orgID, sc.AllowlistDigest, sc.DenylistDigest, sc.AllowPrivate, sc.AllowAny).Scan(&scopeID)
	if err != nil {
		return 0, fmt.Errorf("store: scope snapshot: %w", err)
	}

	tools := r.ToolVersions
	if tools == "" {
		tools = "{}"
	}
	var runPK int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO run
			(org_id, run_id, label, mode, status, targets, scope_id, profile,
			 tool_versions, started_at, finished_at, duration_secs)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12)
		ON CONFLICT (org_id, run_id) DO UPDATE SET
			status = EXCLUDED.status, finished_at = EXCLUDED.finished_at,
			duration_secs = EXCLUDED.duration_secs, scope_id = EXCLUDED.scope_id,
			tool_versions = EXCLUDED.tool_versions
		RETURNING id`,
		orgID, r.RunID, r.Label, r.Mode, r.Status, r.Targets, scopeID, r.Profile,
		tools, r.StartedAt, r.FinishedAt, r.DurationSecs).Scan(&runPK)
	if err != nil {
		return 0, fmt.Errorf("store: upsert run %s: %w", r.RunID, err)
	}

	for _, s := range stages {
		s.Name, s.Note = dbText(s.Name, maxStageName), dbText(s.Note, maxStageNote)
		if s.Name == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO run_stage
				(run_pk, name, seq, status, exit_code, duration_secs, inputs, outputs, note)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (run_pk, name) DO UPDATE SET
				seq = EXCLUDED.seq, status = EXCLUDED.status, exit_code = EXCLUDED.exit_code,
				duration_secs = EXCLUDED.duration_secs, inputs = EXCLUDED.inputs,
				outputs = EXCLUDED.outputs, note = EXCLUDED.note`,
			runPK, s.Name, s.Seq, s.Status, s.ExitCode, s.DurationSecs, s.Inputs, s.Outputs, s.Note); err != nil {
			return 0, fmt.Errorf("store: upsert stage %s: %w", s.Name, err)
		}
	}
	return runPK, nil
}

// UpsertAsset returns the asset with this kind and identifier, creating it on
// first sight and refreshing last_seen_at otherwise.
func UpsertAsset(ctx context.Context, tx *sql.Tx, orgID int64, kind, identifier string) (int64, error) {
	kind, identifier = dbText(kind, maxAttrKey), dbText(identifier, maxAssetID)
	var id int64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO asset (org_id, kind, identifier) VALUES ($1, $2, $3)
		ON CONFLICT (org_id, kind, identifier) DO UPDATE SET last_seen_at = now()
		RETURNING id`, orgID, kind, identifier).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: upsert asset %s %q: %w", kind, identifier, err)
	}
	return id, nil
}

// AddAttribute records an observed fact about an asset, refreshing its
// last_seen_at when the same fact is seen again.
func AddAttribute(ctx context.Context, tx *sql.Tx, assetID int64, key, value, source string, confidence float64) error {
	key, value = dbText(key, maxAttrKey), dbText(value, maxAttrValue)
	source = dbText(source, maxText)
	if key == "" {
		// An empty key cannot happen from the importer and would be a useless row.
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO asset_attribute (asset_id, key, value, source, confidence)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (asset_id, key, value) DO UPDATE SET
			last_seen_at = now(), source = EXCLUDED.source`,
		assetID, key, value, source, confidence)
	if err != nil {
		return fmt.Errorf("store: attribute %s on asset %d: %w", key, assetID, err)
	}
	return nil
}

// Observe records that a run saw an asset at a stage. Seeing it twice is not an
// error.
func Observe(ctx context.Context, tx *sql.Tx, assetID, runPK int64, stage string) error {
	stage = dbText(stage, maxStageName)
	if stage == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO asset_observation (asset_id, run_pk, stage) VALUES ($1, $2, $3)
		ON CONFLICT (asset_id, run_pk, stage) DO NOTHING`, assetID, runPK, stage)
	if err != nil {
		return fmt.Errorf("store: observe asset %d: %w", assetID, err)
	}
	return nil
}

// AssetRow is one line of an inventory listing.
type AssetRow struct {
	Kind       string
	Identifier string
	FirstSeen  time.Time
	LastSeen   time.Time
	Runs       int
}

// ListAssets returns the inventory, newest first, optionally of one kind. Which
// rows come back is decided by row-level security, not by this query.
func ListAssets(ctx context.Context, tx *sql.Tx, kind string, limit int) ([]AssetRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT a.kind, a.identifier, a.first_seen_at, a.last_seen_at,
		       (SELECT count(DISTINCT run_pk) FROM asset_observation o WHERE o.asset_id = a.id)
		FROM asset a
		WHERE ($1 = '' OR a.kind = $1)
		ORDER BY a.last_seen_at DESC, a.id DESC
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

// Attribute is one fact about an asset.
type Attribute struct {
	Key        string
	Value      string
	Source     string
	Confidence float64
	LastSeen   time.Time
}

// Sighting is one run that observed an asset.
type Sighting struct {
	RunID string
	Stage string
	At    time.Time
}

// AssetDetail is everything known about one asset.
type AssetDetail struct {
	AssetRow
	Criticality int
	Attributes  []Attribute
	Sightings   []Sighting
}

// GetAsset returns every asset matching an identifier (the same name can be a
// domain, a host and a url at once), with its attributes and sightings.
func GetAsset(ctx context.Context, tx *sql.Tx, identifier string) ([]AssetDetail, error) {
	type head struct {
		id int64
		d  AssetDetail
	}
	heads, err := func() ([]head, error) {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, kind, identifier, first_seen_at, last_seen_at, criticality
			FROM asset WHERE identifier = $1 ORDER BY kind`, identifier)
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
		if h.d.Sightings, err = sightingsOf(ctx, tx, h.id); err != nil {
			return nil, err
		}
		out = append(out, h.d)
	}
	return out, nil
}

// attributesOf returns every recorded fact about an asset.
func attributesOf(ctx context.Context, tx *sql.Tx, assetID int64) ([]Attribute, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT key, value, source, confidence, last_seen_at
		FROM asset_attribute WHERE asset_id = $1 ORDER BY key, value`, assetID)
	if err != nil {
		return nil, fmt.Errorf("store: attributes: %w", err)
	}
	defer rows.Close()
	var out []Attribute
	for rows.Next() {
		var a Attribute
		if err := rows.Scan(&a.Key, &a.Value, &a.Source, &a.Confidence, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// sightingsOf returns the most recent runs that observed an asset.
func sightingsOf(ctx context.Context, tx *sql.Tx, assetID int64) ([]Sighting, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT r.run_id, o.stage, o.observed_at
		FROM asset_observation o JOIN run r ON r.id = o.run_pk
		WHERE o.asset_id = $1 ORDER BY o.observed_at DESC LIMIT 50`, assetID)
	if err != nil {
		return nil, fmt.Errorf("store: sightings: %w", err)
	}
	defer rows.Close()
	var out []Sighting
	for rows.Next() {
		var s Sighting
		if err := rows.Scan(&s.RunID, &s.Stage, &s.At); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// FindingRow is one stored finding with the asset it was found on.
type FindingRow struct {
	Kind        string
	Identifier  string
	Criticality int
	Value       string
	Source      string
}

// ListFindings returns every finding recorded against the tenant's assets.
// Findings are asset attributes with the key "finding".
func ListFindings(ctx context.Context, tx *sql.Tx) ([]FindingRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.kind, a.identifier, a.criticality, t.value, t.source
		FROM asset_attribute t JOIN asset a ON a.id = t.asset_id
		WHERE t.key = 'finding'
		ORDER BY a.identifier, t.value`)
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

// SetCriticality records the operator's rating of an asset, 0 (unset) to 100, and
// returns how many assets it applied to. The same identifier can be several assets
// (a name that is both a domain and a host), and a rating describes the thing, not
// the kind. Criticality comes only from the operator, never from inference.
func SetCriticality(ctx context.Context, tx *sql.Tx, identifier string, value int) (int64, error) {
	if value < 0 || value > 100 {
		return 0, fmt.Errorf("store: criticality %d is outside 0 to 100", value)
	}
	res, err := tx.ExecContext(ctx,
		"UPDATE asset SET criticality = $2 WHERE identifier = $1", identifier, value)
	if err != nil {
		return 0, fmt.Errorf("store: set criticality: %w", err)
	}
	return res.RowsAffected()
}
