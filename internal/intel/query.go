package intel

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// SourceStatus is the sync state of one source.
type SourceStatus struct {
	Source   string
	Records  int
	Version  string
	SyncedAt time.Time
	ETag     string
}

// Status returns the sync state of every source that has been synced, plus the
// number of distinct CVEs known.
func Status(ctx context.Context, tx *sql.Tx) (sources []SourceStatus, cves int, err error) {
	rows, err := tx.QueryContext(ctx,
		"SELECT source, records, version, synced_at, etag FROM source_watermark ORDER BY source")
	if err != nil {
		return nil, 0, fmt.Errorf("intel: status: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s SourceStatus
		if err := rows.Scan(&s.Source, &s.Records, &s.Version, &s.SyncedAt, &s.ETag); err != nil {
			return nil, 0, err
		}
		sources = append(sources, s)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM cve").Scan(&cves); err != nil {
		return nil, 0, fmt.Errorf("intel: count cves: %w", err)
	}
	return sources, cves, nil
}

// Detail is everything known about one CVE.
type Detail struct {
	CVE   string
	Known bool // the cve row exists at all
	KEV   *KEVDetail
	EPSS  *EPSSDetail
	NVD   *NVDDetail
}

// NVDDetail is the NVD record for a CVE, when it has been fetched.
type NVDDetail struct {
	CVSSVersion  string
	CVSSScore    *float32
	CVSSSeverity string
	CVSSVector   string
	Description  string
	Published    *time.Time
	CWEs         []string
	FetchedAt    time.Time
}

// KEVDetail is the CISA catalogue entry for a CVE.
type KEVDetail struct {
	VendorProject   string
	Product         string
	Name            string
	DateAdded       time.Time
	Description     string
	RequiredAction  string
	DueDate         *time.Time
	KnownRansomware bool
	CWEs            []string
}

// EPSSDetail is the EPSS score for a CVE.
type EPSSDetail struct {
	Score      float32
	Percentile float32
	ScoreDate  time.Time
	Model      string
}

// Show returns what is known about a CVE. An id no source has mentioned comes
// back with Known false, which is a different answer from "known and not
// exploited", and the caller must not blur them.
func Show(ctx context.Context, tx *sql.Tx, id string) (*Detail, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	d := &Detail{CVE: id}

	var one int
	err := tx.QueryRowContext(ctx, "SELECT 1 FROM cve WHERE cve_id = $1", id).Scan(&one)
	if err == sql.ErrNoRows {
		return d, nil
	}
	if err != nil {
		return nil, fmt.Errorf("intel: look up %s: %w", id, err)
	}
	d.Known = true

	k := &KEVDetail{}
	var due sql.NullTime
	var cwes []string
	err = tx.QueryRowContext(ctx, `
		SELECT vendor_project, product, vulnerability_name, date_added, short_description,
		       required_action, due_date, known_ransomware, cwes
		FROM cve_kev_cisa WHERE cve_id = $1`, id).
		Scan(&k.VendorProject, &k.Product, &k.Name, &k.DateAdded, &k.Description,
			&k.RequiredAction, &due, &k.KnownRansomware, &cwes)
	switch {
	case err == nil:
		if due.Valid {
			k.DueDate = &due.Time
		}
		k.CWEs = cwes
		d.KEV = k
	case err != sql.ErrNoRows:
		return nil, fmt.Errorf("intel: KEV for %s: %w", id, err)
	}

	e := &EPSSDetail{}
	err = tx.QueryRowContext(ctx, `
		SELECT epss, percentile, score_date, model_version FROM cve_epss WHERE cve_id = $1`, id).
		Scan(&e.Score, &e.Percentile, &e.ScoreDate, &e.Model)
	switch {
	case err == nil:
		d.EPSS = e
	case err != sql.ErrNoRows:
		return nil, fmt.Errorf("intel: EPSS for %s: %w", id, err)
	}

	n := &NVDDetail{}
	var score sql.NullFloat64
	var pub sql.NullTime
	var cwes2 []string
	err = tx.QueryRowContext(ctx, `
		SELECT cvss_version, cvss_score, cvss_severity, cvss_vector, description,
		       published_at, cwes, fetched_at
		FROM cve_nvd WHERE cve_id = $1`, id).
		Scan(&n.CVSSVersion, &score, &n.CVSSSeverity, &n.CVSSVector, &n.Description,
			&pub, &cwes2, &n.FetchedAt)
	switch {
	case err == nil:
		if score.Valid {
			f := float32(score.Float64)
			n.CVSSScore = &f
		}
		if pub.Valid {
			n.Published = &pub.Time
		}
		n.CWEs = cwes2
		d.NVD = n
	case err != sql.ErrNoRows:
		return nil, fmt.Errorf("intel: NVD for %s: %w", id, err)
	}
	return d, nil
}

// SearchHit is one result of a catalogue search.
type SearchHit struct {
	CVE       string
	Vendor    string
	Product   string
	Name      string
	DateAdded time.Time
	EPSS      *float32
}

// Search finds known-exploited vulnerabilities by vendor, product, name or CVE
// id. The text is matched as a literal substring, not as a pattern.
func Search(ctx context.Context, tx *sql.Tx, text string, limit int) ([]SearchHit, error) {
	if limit <= 0 {
		limit = 50
	}
	// Escape LIKE's own metacharacters so a search for "100%" means those
	// characters and nothing else.
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.TrimSpace(text))
	rows, err := tx.QueryContext(ctx, `
		SELECT k.cve_id, k.vendor_project, k.product, k.vulnerability_name, k.date_added, e.epss
		FROM cve_kev_cisa k LEFT JOIN cve_epss e USING (cve_id)
		WHERE k.cve_id ILIKE '%' || $1 || '%' ESCAPE '\'
		   OR k.vendor_project ILIKE '%' || $1 || '%' ESCAPE '\'
		   OR k.product ILIKE '%' || $1 || '%' ESCAPE '\'
		   OR k.vulnerability_name ILIKE '%' || $1 || '%' ESCAPE '\'
		ORDER BY k.date_added DESC, k.cve_id
		LIMIT $2`, esc, limit)
	if err != nil {
		return nil, fmt.Errorf("intel: search: %w", err)
	}
	defer rows.Close()
	var out []SearchHit
	for rows.Next() {
		var h SearchHit
		var ep sql.NullFloat64
		if err := rows.Scan(&h.CVE, &h.Vendor, &h.Product, &h.Name, &h.DateAdded, &ep); err != nil {
			return nil, err
		}
		if ep.Valid {
			f := float32(ep.Float64)
			h.EPSS = &f
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
