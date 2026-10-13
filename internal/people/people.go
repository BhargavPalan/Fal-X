// Package people turns the email addresses the recon sources harvested into the
// people graph: it derives a contact from each personal address, links the two, and
// infers the address convention each estate domain uses.
//
// It runs as a pass over the graph after collection, like exposure and correlation,
// and reads and writes only what is already there — it sends no packet to any mail
// server. Deriving "Jane Doe" from jane.doe@acme.com and recording that acme.com
// addresses are {first}.{last} is an inference, stored with a confidence below an
// observed fact and never presented as confirmed. Confirming an address exists (an
// SMTP probe) is an active step that belongs to a separate, gated stage, not here.
package people

import (
	"context"
	"database/sql"
	"sort"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// source names this pass as the provenance of every fact and edge it writes.
const source = "people"

// Run derives contacts and address conventions for the tenant. The transaction is
// opened for the organization, so row-level security scopes every read and write.
func Run(ctx context.Context, db *store.DB, orgID int64) error {
	return db.InTx(ctx, func(tx *sql.Tx) error {
		emails, err := loadEmails(ctx, tx)
		if err != nil {
			return err
		}
		domains, err := loadDomains(ctx, tx)
		if err != nil {
			return err
		}
		return derive(ctx, tx, orgID, emails, domains)
	})
}

// emailRow is one email entity with the distance that any contact derived from it
// inherits.
type emailRow struct {
	id   int64
	addr string
	dist int
}

// loadEmails reads the tenant's email entities. The result set is fully read and
// closed before any write, because writing on a transaction with an open result set
// is not allowed.
func loadEmails(ctx context.Context, tx *sql.Tx) ([]emailRow, error) {
	rows, err := tx.QueryContext(ctx,
		"SELECT id, key, seed_distance FROM entity WHERE type = 'email' ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []emailRow
	for rows.Next() {
		var r emailRow
		if err := rows.Scan(&r.id, &r.addr, &r.dist); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// loadDomains maps each estate domain's key to its id, so address-format inference is
// recorded only on domains the run actually owns, not on a third-party address's
// domain (a harvested gmail.com contact must not stamp a convention on gmail.com).
func loadDomains(ctx context.Context, tx *sql.Tx) (map[string]int64, error) {
	rows, err := tx.QueryContext(ctx,
		"SELECT key, id FROM entity WHERE type = 'domain'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var key string
		var id int64
		if err := rows.Scan(&key, &id); err != nil {
			return nil, err
		}
		out[key] = id
	}
	return out, rows.Err()
}

// derive writes the contacts, the address classifications, and the per-domain format
// votes. It runs after the reads above are closed.
func derive(ctx context.Context, tx *sql.Tx, orgID int64, emails []emailRow, domains map[string]int64) error {
	// votes[domainKey][format] counts how many of a domain's personal addresses use
	// each naming format, so the dominant one can be recorded as the convention.
	votes := map[string]map[string]int{}

	for _, em := range emails {
		local, dom, ok := splitEmail(em.addr)
		if !ok {
			continue
		}
		kind := classifyLocal(local)
		if err := graph.AddFact(ctx, tx, graph.Ref(em.id), "address_kind", kind, source, true, 0.8, 0); err != nil {
			return err
		}
		if kind != "personal" {
			continue
		}
		display, format, ok := personFromLocal(local)
		if !ok {
			continue
		}
		// Key the contact by the lowercased name so case variants merge. This can merge
		// two different people who share a name; that is the documented low-merge trade
		// for people, so the contact and its link carry a confidence below an observed fact.
		person, err := graph.Resolve(ctx, tx, orgID, graph.TypePerson, lowerKey(display), display, em.dist)
		if err != nil {
			return err
		}
		if err := graph.AddEdge(ctx, tx, orgID, person, graph.Ref(em.id),
			graph.RelHasEmail, graph.TypePerson, graph.TypeEmail, 0.7); err != nil {
			return err
		}
		if err := graph.AddFact(ctx, tx, person, "name", display, source, true, 0.6, 0); err != nil {
			return err
		}
		if _, estate := domains[dom]; estate {
			if votes[dom] == nil {
				votes[dom] = map[string]int{}
			}
			votes[dom][format]++
		}
	}

	return recordFormats(ctx, tx, votes, domains)
}

// recordFormats writes each estate domain's dominant address format as a fact, with a
// confidence that grows with how many addresses agree, capped so an inference never
// reads as certain.
func recordFormats(ctx context.Context, tx *sql.Tx, votes map[string]map[string]int, domains map[string]int64) error {
	for dom, counts := range votes {
		best, n := dominant(counts)
		if best == "" {
			continue
		}
		conf := 0.4 + 0.1*float64(n)
		if conf > 0.9 {
			conf = 0.9
		}
		if err := graph.AddFact(ctx, tx, graph.Ref(domains[dom]), "email_format", best, source, true, conf, 0); err != nil {
			return err
		}
	}
	return nil
}

// dominant returns the most-voted format and its count. Ties are broken by format
// string so the result is deterministic across runs.
func dominant(counts map[string]int) (string, int) {
	formats := make([]string, 0, len(counts))
	for f := range counts {
		formats = append(formats, f)
	}
	sort.Strings(formats)
	best, bestN := "", 0
	for _, f := range formats {
		if counts[f] > bestN {
			best, bestN = f, counts[f]
		}
	}
	return best, bestN
}

// lowerKey lowercases a display name for use as the person's canonical key.
func lowerKey(display string) string {
	b := []byte(display)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
