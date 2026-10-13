package intel

import (
	"context"
	"database/sql"
	"errors"
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

	// Via is the identifier the caller asked for when it was an alias of CVE, such
	// as a GHSA id. It is empty when the CVE id itself was given.
	Via string
	// Aliases are the other identifiers OSV advisories give this CVE.
	Aliases []string
	// Advisories are the OSV advisories that name this CVE.
	Advisories []AdvisoryRef
	// Products are the vendor:product pairs NVD lists as vulnerable, up to 20.
	Products []string
}

// AdvisoryRef is an OSV advisory that names a CVE.
type AdvisoryRef struct {
	Ecosystem string
	ID        string
	Summary   string
	Withdrawn bool
	Packages  []string
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
//
// An identifier that is not a CVE id, such as a GHSA id, is resolved through the
// OSV aliases to the CVE it names; Via records what was asked for.
func Show(ctx context.Context, tx *sql.Tx, id string) (*Detail, error) {
	asked := strings.TrimSpace(id)
	id = strings.ToUpper(asked)
	d := &Detail{CVE: id}

	if !cveID.MatchString(id) {
		var cve string
		err := tx.QueryRowContext(ctx,
			"SELECT cve_id FROM cve_alias WHERE alias = $1 ORDER BY cve_id LIMIT 1", asked).Scan(&cve)
		if errors.Is(err, sql.ErrNoRows) {
			d.CVE = asked
			return d, nil
		}
		if err != nil {
			return nil, fmt.Errorf("intel: resolve %s: %w", asked, err)
		}
		id, d.CVE, d.Via = cve, cve, asked
	}

	var one int
	err := tx.QueryRowContext(ctx, "SELECT 1 FROM cve WHERE cve_id = $1", id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return d, nil
	}
	if err != nil {
		return nil, fmt.Errorf("intel: look up %s: %w", id, err)
	}
	d.Known = true
	if err := loadAdvisories(ctx, tx, id, d); err != nil {
		return nil, err
	}
	if err := loadProducts(ctx, tx, id, d); err != nil {
		return nil, err
	}

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

// loadAdvisories fills in the aliases and OSV advisories that name a CVE.
func loadAdvisories(ctx context.Context, tx *sql.Tx, id string, d *Detail) error {
	var err error
	if d.Aliases, err = aliasesOf(ctx, tx, id); err != nil {
		return err
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT a.ecosystem, a.osv_id, a.summary, a.withdrawn IS NOT NULL,
		       COALESCE(array_agg(DISTINCT f.package_name) FILTER (WHERE f.package_name <> ''), '{}')
		FROM osv_advisory a
		JOIN (SELECT DISTINCT ecosystem, osv_id FROM cve_alias WHERE cve_id = $1) x
		     ON x.ecosystem = a.ecosystem AND x.osv_id = a.osv_id
		LEFT JOIN osv_affected f ON f.ecosystem = a.ecosystem AND f.osv_id = a.osv_id
		GROUP BY a.ecosystem, a.osv_id, a.summary, a.withdrawn
		ORDER BY a.osv_id, a.ecosystem
		LIMIT 50`, id)
	if err != nil {
		return fmt.Errorf("intel: advisories for %s: %w", id, err)
	}
	defer rows.Close()
	for rows.Next() {
		var r AdvisoryRef
		if err := rows.Scan(&r.Ecosystem, &r.ID, &r.Summary, &r.Withdrawn, &r.Packages); err != nil {
			return err
		}
		d.Advisories = append(d.Advisories, r)
	}
	return rows.Err()
}

// loadProducts fills in the products NVD lists as vulnerable for a CVE.
func loadProducts(ctx context.Context, tx *sql.Tx, id string, d *Detail) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT vendor || ':' || product FROM cve_cpe
		WHERE cve_id = $1 AND vulnerable ORDER BY 1 LIMIT 20`, id)
	if err != nil {
		return fmt.Errorf("intel: products for %s: %w", id, err)
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return err
		}
		d.Products = append(d.Products, p)
	}
	return rows.Err()
}

// ProductHit is a CVE that NVD lists against a product.
type ProductHit struct {
	CVE   string
	CVSS  *float32
	KEV   bool
	EPSS  *float32
	Range string
}

// ByProduct lists the CVEs NVD names for a vendor and product, known-exploited
// first and then by CVSS score. Vendor and product are matched as CPE writes them,
// in lower case.
func ByProduct(ctx context.Context, tx *sql.Tx, vendor, product string, limit int) ([]ProductHit, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT c.cve_id, n.cvss_score, k.cve_id IS NOT NULL, e.epss,
		       COALESCE(string_agg(DISTINCT c.ver, ' | '), '')
		FROM (
			SELECT cve_id,
			       CASE WHEN version NOT IN ('*', '-') THEN version
			            ELSE trim(both ' ' from
			                 CASE WHEN start_including <> '' THEN '>=' || start_including || ' ' ELSE '' END ||
			                 CASE WHEN start_excluding <> '' THEN '>' || start_excluding || ' ' ELSE '' END ||
			                 CASE WHEN end_including <> '' THEN '<=' || end_including ELSE '' END ||
			                 CASE WHEN end_excluding <> '' THEN '<' || end_excluding ELSE '' END) END AS ver
			FROM cve_cpe WHERE vendor = $1 AND product = $2 AND vulnerable
		) c
		LEFT JOIN cve_nvd n USING (cve_id)
		LEFT JOIN cve_kev_cisa k USING (cve_id)
		LEFT JOIN cve_epss e USING (cve_id)
		GROUP BY c.cve_id, n.cvss_score, k.cve_id, e.epss
		ORDER BY (k.cve_id IS NULL), n.cvss_score DESC NULLS LAST, c.cve_id
		LIMIT $3`, strings.ToLower(vendor), strings.ToLower(product), limit)
	if err != nil {
		return nil, fmt.Errorf("intel: product lookup: %w", err)
	}
	defer rows.Close()
	var out []ProductHit
	for rows.Next() {
		var h ProductHit
		var cvss, epss sql.NullFloat64
		if err := rows.Scan(&h.CVE, &cvss, &h.KEV, &epss, &h.Range); err != nil {
			return nil, err
		}
		if cvss.Valid {
			f := float32(cvss.Float64)
			h.CVSS = &f
		}
		if epss.Valid {
			f := float32(epss.Float64)
			h.EPSS = &f
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// aliasesOf returns every identifier OSV advisories give a CVE.
func aliasesOf(ctx context.Context, tx *sql.Tx, id string) ([]string, error) {
	rows, err := tx.QueryContext(ctx,
		"SELECT DISTINCT alias FROM cve_alias WHERE cve_id = $1 ORDER BY alias", id)
	if err != nil {
		return nil, fmt.Errorf("intel: aliases for %s: %w", id, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
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
