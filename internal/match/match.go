// Package match joins what was observed on an organization's assets to the
// vulnerability data, and says how much each join can be trusted.
//
// An observation is a technology or server banner (internal/store.ListEvidence).
// It is read as a CPE vendor and product, and the CVEs NVD lists against that
// product are tested against the observed version. The result is a claim of one of
// four kinds, each with a confidence, so a reader can tell "the version is inside a
// listed range" from "the product has a known-exploited CVE and nobody knows the
// version".
package match

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// The kinds of claim a match makes. See migration 0008.
const (
	TierAffected    = "affected"
	TierConditional = "conditional"
	TierPossible    = "possible"
	TierUnverified  = "unverified"
)

// Summary says what a run did.
type Summary struct {
	// Observations is how many software sightings were read from the evidence, and
	// Products how many distinct CPE products they resolved to.
	Observations int
	Products     int
	// Matches counts the stored rows by tier.
	Matches map[string]int
	// Assets is how many assets have at least one match.
	Assets int
}

// Total is the number of stored matches.
func (s Summary) Total() int {
	n := 0
	for _, c := range s.Matches {
		n += c
	}
	return n
}

type sighting struct {
	assetID int64
	sw      Software
	prod    Product
	exact   bool
}

type cpeRow struct {
	cve     string
	cfg     int
	cfgOp   string
	version string
	rng     Range
}

type matcher struct {
	ctx context.Context
	tx  *sql.Tx

	rows  map[Product][]cpeRow
	kev   map[Product]map[string]bool
	guess map[string][]Product
	conds map[Product]map[string][]string
}

// Run matches the tenant's assets and replaces its stored matches. The transaction
// must be scoped to the organization.
func Run(ctx context.Context, tx *sql.Tx, orgID int64) (Summary, error) {
	m := &matcher{
		ctx: ctx, tx: tx,
		rows: map[Product][]cpeRow{}, kev: map[Product]map[string]bool{},
		guess: map[string][]Product{}, conds: map[Product]map[string][]string{},
	}
	sum := Summary{Matches: map[string]int{}}

	evidence, err := store.ListEvidence(ctx, tx)
	if err != nil {
		return sum, err
	}
	sightings, err := m.sightings(evidence)
	if err != nil {
		return sum, err
	}
	sum.Observations = len(sightings)

	var out []store.MatchRow
	products := map[Product]bool{}
	assets := map[int64]bool{}
	for _, s := range sightings {
		products[s.prod] = true
		if s.sw.Version != "" {
			conf := 0.9
			if !s.exact {
				conf = 0.5
			}
			value := s.prod.Vendor + ":" + s.prod.Product + " " + s.sw.Version
			if err := graph.AddFact(ctx, tx, graph.Ref(s.assetID), "software", value, "match", true, conf, 0); err != nil {
				return sum, err
			}
		}
		rows, err := m.evaluate(s)
		if err != nil {
			return sum, err
		}
		for _, r := range rows {
			sum.Matches[r.Tier]++
			assets[r.AssetID] = true
		}
		out = append(out, rows...)
	}
	sum.Products = len(products)
	sum.Assets = len(assets)

	if err := store.ReplaceMatches(ctx, tx, orgID, out); err != nil {
		return sum, err
	}
	return sum, nil
}

// sightings reads every observation and resolves it to a product, once per asset,
// product and version.
func (m *matcher) sightings(evidence []store.Evidence) ([]sighting, error) {
	var out []sighting
	seen := map[string]bool{}
	for _, e := range evidence {
		for _, sw := range Observations(e.Key, e.Value) {
			if sw.Name == "" {
				continue
			}
			var prods []Product
			exact := false
			if p, ok := Resolve(sw.Name); ok {
				prods, exact = []Product{p}, true
			} else if sw.Version != "" {
				var err error
				if prods, err = m.guessProducts(sw.Name); err != nil {
					return nil, err
				}
			}
			for _, p := range prods {
				key := fmt.Sprintf("%d|%s|%s|%s", e.AssetID, p.Vendor, p.Product, sw.Version)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, sighting{assetID: e.AssetID, sw: sw, prod: p, exact: exact})
			}
		}
	}
	return out, nil
}

// guessProducts looks an unrecognised name up as a CPE product name. A name that
// several vendors use is too ambiguous to act on.
func (m *matcher) guessProducts(name string) ([]Product, error) {
	g := guess(name)
	if cached, ok := m.guess[g]; ok {
		return cached, nil
	}
	rows, err := m.tx.QueryContext(m.ctx,
		"SELECT DISTINCT vendor FROM cve_cpe WHERE product = $1 AND vulnerable LIMIT 4", g)
	if err != nil {
		return nil, fmt.Errorf("match: look up %q: %w", g, err)
	}
	defer rows.Close()
	var found []Product
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		found = append(found, Product{v, g})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(found) > 2 {
		found = nil
	}
	m.guess[g] = found
	return found, nil
}

// load reads, once, the vulnerable CPE entries for a product and the CVEs among
// them that are known exploited.
func (m *matcher) load(p Product) ([]cpeRow, error) {
	if rows, ok := m.rows[p]; ok {
		return rows, nil
	}
	rs, err := m.tx.QueryContext(m.ctx, `
		SELECT cve_id, config_seq, config_operator, version,
		       start_including, start_excluding, end_including, end_excluding
		FROM cve_cpe WHERE vendor = $1 AND product = $2 AND vulnerable
		ORDER BY cve_id, config_seq, node_seq, match_seq`, p.Vendor, p.Product)
	if err != nil {
		return nil, fmt.Errorf("match: load %s:%s: %w", p.Vendor, p.Product, err)
	}
	defer rs.Close()
	var rows []cpeRow
	for rs.Next() {
		var r cpeRow
		if err := rs.Scan(&r.cve, &r.cfg, &r.cfgOp, &r.version, &r.rng.StartIncluding,
			&r.rng.StartExcluding, &r.rng.EndIncluding, &r.rng.EndExcluding); err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	m.rows[p] = rows

	kev := map[string]bool{}
	ks, err := m.tx.QueryContext(m.ctx, `
		SELECT DISTINCT c.cve_id FROM cve_cpe c JOIN cve_kev_cisa k USING (cve_id)
		WHERE c.vendor = $1 AND c.product = $2 AND c.vulnerable`, p.Vendor, p.Product)
	if err != nil {
		return nil, fmt.Errorf("match: known-exploited for %s:%s: %w", p.Vendor, p.Product, err)
	}
	defer ks.Close()
	for ks.Next() {
		var id string
		if err := ks.Scan(&id); err != nil {
			return nil, err
		}
		kev[id] = true
	}
	m.kev[p] = kev
	return rows, ks.Err()
}

// conditions returns, for the CVEs a product matched, what else NVD requires in the
// same configuration: the entries it lists as not vulnerable, such as an operating
// system. The key is "CVE|config".
func (m *matcher) conditionsFor(p Product, cves []string) (map[string][]string, error) {
	if c, ok := m.conds[p]; ok {
		return c, nil
	}
	rs, err := m.tx.QueryContext(m.ctx, `
		SELECT cve_id, config_seq, criteria FROM cve_cpe
		WHERE cve_id = ANY($1::text[]) AND NOT vulnerable
		ORDER BY cve_id, config_seq, node_seq, match_seq`, cves)
	if err != nil {
		return nil, fmt.Errorf("match: conditions for %s:%s: %w", p.Vendor, p.Product, err)
	}
	defer rs.Close()
	out := map[string][]string{}
	for rs.Next() {
		var id, crit string
		var cfg int
		if err := rs.Scan(&id, &cfg, &crit); err != nil {
			return nil, err
		}
		k := fmt.Sprintf("%s|%d", id, cfg)
		out[k] = append(out[k], crit)
	}
	m.conds[p] = out
	return out, rs.Err()
}

type candidate struct {
	cve    string
	reason string
	conds  []string
}

// evaluate returns the matches for one sighting.
func (m *matcher) evaluate(s sighting) ([]store.MatchRow, error) {
	rows, err := m.load(s.prod)
	if err != nil {
		return nil, err
	}

	base := store.MatchRow{
		AssetID: s.assetID, Evidence: s.sw.Evidence, Software: s.sw.Name, Version: s.sw.Version,
		Vendor: s.prod.Vendor, Product: s.prod.Product,
	}
	caveat := ""
	if s.sw.Distro != "" {
		caveat = "The banner names " + s.sw.Distro + ", which patches software without changing its " +
			"version number; confirm the installed package version."
	}

	if s.sw.Version == "" {
		var out []store.MatchRow
		for _, id := range sortedKeys(m.kev[s.prod]) {
			r := base
			r.CVE, r.Tier, r.Confidence = id, TierPossible, "low"
			r.Reason = "the product is present, its version is not known, and this CVE is known to be exploited"
			r.Caveat = caveat
			out = append(out, r)
		}
		return out, nil
	}

	needs, err := m.conditionsFor(s.prod, cvesOf(rows))
	if err != nil {
		return nil, err
	}
	best := map[string]*candidate{}
	var order []string
	for _, r := range rows {
		reason, ok := applies(s.sw.Version, r)
		if !ok {
			continue
		}
		var need []string
		if r.cfgOp == "AND" {
			need = needs[fmt.Sprintf("%s|%d", r.cve, r.cfg)]
		}
		c := best[r.cve]
		switch {
		case c == nil:
			best[r.cve] = &candidate{cve: r.cve, reason: reason, conds: need}
			order = append(order, r.cve)
		case len(c.conds) > 0 && len(need) == 0:
			// A configuration with nothing else required settles it.
			c.reason, c.conds = reason, nil
		}
	}

	out := make([]store.MatchRow, 0, len(order))
	for _, id := range order {
		c := best[id]
		r := base
		r.CVE, r.Reason, r.Caveat = c.cve, c.reason, caveat
		switch {
		case !s.exact:
			r.Tier, r.Confidence = TierUnverified, "low"
			r.Reason = "the product was guessed from its name; " + c.reason
		case len(c.conds) > 0:
			r.Tier, r.Confidence = TierConditional, "medium"
			r.Conditions = "NVD lists this only together with: " + strings.Join(firstN(c.conds, 3), ", ")
		default:
			r.Tier, r.Confidence = TierAffected, "high"
		}
		if caveat != "" && r.Confidence == "high" {
			r.Confidence = "medium"
		}
		out = append(out, r)
	}
	return out, nil
}

// applies tests one CPE entry against an observed version.
func applies(version string, r cpeRow) (string, bool) {
	switch r.version {
	case "-":
		return "", false
	case "*", "":
		if !r.rng.Contains(version) {
			return "", false
		}
		if !r.rng.Bounded() {
			return "NVD lists every version of the product", true
		}
		return fmt.Sprintf("version %s is inside %s, which NVD lists as vulnerable", version, r.rng.String()), true
	default:
		if Compare(version, r.version) != 0 {
			return "", false
		}
		return fmt.Sprintf("NVD lists version %s as vulnerable", r.version), true
	}
}

// String writes a range the way NVD's bounds read, such as ">=2.4.0 <2.4.50".
func (r Range) String() string {
	var parts []string
	if r.StartIncluding != "" {
		parts = append(parts, ">="+r.StartIncluding)
	}
	if r.StartExcluding != "" {
		parts = append(parts, ">"+r.StartExcluding)
	}
	if r.EndIncluding != "" {
		parts = append(parts, "<="+r.EndIncluding)
	}
	if r.EndExcluding != "" {
		parts = append(parts, "<"+r.EndExcluding)
	}
	return strings.Join(parts, " ")
}

func cvesOf(rows []cpeRow) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		if !seen[r.cve] {
			seen[r.cve] = true
			out = append(out, r.cve)
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Listed is a stored match with what the CVE data adds to it.
type Listed struct {
	Asset      string
	Software   string
	Version    string
	CVE        string
	Tier       string
	Confidence string
	KEV        bool
	CVSS       *float32
	Reason     string
	Conditions string
	Caveat     string
}

// List returns the tenant's matches, known-exploited first and then by tier and
// CVSS score. asset limits it to one asset identifier.
func List(ctx context.Context, tx *sql.Tx, asset string, limit int) ([]Listed, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT e.key, m.software, m.version, m.cve_id, m.tier, m.confidence,
		       k.cve_id IS NOT NULL, n.cvss_score, m.reason, m.conditions, m.caveat
		FROM match_result m
		JOIN entity e ON e.id = m.entity_id
		LEFT JOIN cve_kev_cisa k ON k.cve_id = m.cve_id
		LEFT JOIN cve_nvd n ON n.cve_id = m.cve_id
		WHERE ($1 = '' OR e.key = $1)
		ORDER BY (k.cve_id IS NULL),
		         CASE m.tier WHEN 'affected' THEN 0 WHEN 'conditional' THEN 1 WHEN 'possible' THEN 2 ELSE 3 END,
		         n.cvss_score DESC NULLS LAST, e.key, m.cve_id
		LIMIT $2`, asset, limit)
	if err != nil {
		return nil, fmt.Errorf("match: list: %w", err)
	}
	defer rows.Close()
	var out []Listed
	for rows.Next() {
		var l Listed
		var cvss sql.NullFloat64
		if err := rows.Scan(&l.Asset, &l.Software, &l.Version, &l.CVE, &l.Tier, &l.Confidence,
			&l.KEV, &cvss, &l.Reason, &l.Conditions, &l.Caveat); err != nil {
			return nil, err
		}
		if cvss.Valid {
			f := float32(cvss.Float64)
			l.CVSS = &f
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
