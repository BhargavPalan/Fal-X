// Package origin discovers the real server behind a CDN or WAF. A host fronted by a
// CDN hides its origin IP, but the origin is often still reachable directly and still
// in the estate's own address space (a mail server, a sibling that is not proxied, an
// IP in the same netblock). This pass takes each CDN-fronted host, fetches its true
// response through the CDN, then asks every candidate estate IP for that host by name;
// an IP that returns the same response is the origin.
//
// The link it writes (origin_of) is inferred, never asserted: the graph flags it, and
// prioritise treats it as a hypothesis. The confirmation — requesting the IP with the
// host's own Host header and matching the body — is what separates this from a guess.
package origin

import (
	"context"
	"database/sql"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// maxHosts and maxCandidates bound the work so a large estate cannot turn this into an
// unbounded scan.
const (
	maxHosts      = 100
	maxCandidates = 100
)

// Prober fetches responses for comparison. It is an interface so the pass is tested
// without the network.
type Prober interface {
	// Signature fetches the host through its normal (CDN) path and returns a comparable
	// signature of the response, and whether the host answered.
	Signature(ctx context.Context, host string) (string, bool)
	// Probe fetches ip directly while claiming to be host (via the Host header) and
	// returns the response signature, and whether it answered.
	Probe(ctx context.Context, ip, host string) (string, bool)
}

// Run finds origin IPs for CDN-fronted hosts and records the inferred origin_of edges.
func Run(ctx context.Context, db *store.DB, orgID int64, prober Prober) error {
	cdnHosts, resolutions, err := gather(ctx, db)
	if err != nil {
		return err
	}
	if len(cdnHosts) == 0 {
		return nil
	}

	// Probe outside any transaction: this is network I/O and must not hold a database
	// connection open.
	type found struct{ host, ip string }
	var hits []found
	for _, host := range cdnHosts {
		sig, ok := prober.Signature(ctx, host)
		if !ok || sig == "" {
			continue
		}
		rd := registeredDomain(host)
		own := ownIPs(host, resolutions)
		seen := 0
		for ip := range resolutions.byDomain[rd] {
			if _, isOwn := own[ip]; isOwn || seen >= maxCandidates {
				continue
			}
			seen++
			if psig, ok := prober.Probe(ctx, ip, host); ok && psig == sig {
				hits = append(hits, found{host, ip})
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}

	return db.InTx(ctx, func(tx *sql.Tx) error {
		for _, h := range hits {
			host, err := graph.Resolve(ctx, tx, orgID, graph.TypeHost, h.host, h.host, 0)
			if err != nil {
				return err
			}
			ip, err := graph.Resolve(ctx, tx, orgID, graph.TypeIP, h.ip, h.ip, 0)
			if err != nil {
				return err
			}
			if err := graph.AddEdge(ctx, tx, orgID, ip, host, graph.RelOriginOf, graph.TypeIP, graph.TypeHost, 0.6); err != nil {
				return err
			}
			if err := graph.AddFact(ctx, tx, host, "finding", "medium origin-ip-exposed "+h.ip, "origin", true, 0.6, 0); err != nil {
				return err
			}
			if err := graph.AddFact(ctx, tx, host, "exposure", "origin_exposed", "origin", true, 0.6, 0); err != nil {
				return err
			}
		}
		return nil
	})
}

// resolveSet holds host->ip resolutions grouped by the host's registrable domain, plus
// a per-host set of its own IPs.
type resolveSet struct {
	byDomain map[string]map[string]struct{} // registrable domain -> set of IPs
	byHost   map[string]map[string]struct{} // host -> set of IPs
}

// gather reads the CDN-fronted hosts and all host->ip resolutions in one short
// transaction.
func gather(ctx context.Context, db *store.DB) ([]string, resolveSet, error) {
	rs := resolveSet{byDomain: map[string]map[string]struct{}{}, byHost: map[string]map[string]struct{}{}}
	var cdnHosts []string
	err := db.InTx(ctx, func(tx *sql.Tx) error {
		hosts, err := cdnFrontedHosts(ctx, tx)
		if err != nil {
			return err
		}
		cdnHosts = hosts
		return eachResolution(ctx, tx, func(host, ip string) {
			add(rs.byHost, host, ip)
			add(rs.byDomain, registeredDomain(host), ip)
		})
	})
	return cdnHosts, rs, err
}

// cdnFrontedHosts returns the hosts tagged as sitting behind a CDN or WAF.
func cdnFrontedHosts(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT e.key
		FROM entity e JOIN entity_fact f ON f.entity_id = e.id
		WHERE e.type = 'host' AND f.key IN ('cdn', 'waf')
		LIMIT $1`, maxHosts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// eachResolution calls fn for every host->ip resolves_to edge.
func eachResolution(ctx context.Context, tx *sql.Tx, fn func(host, ip string)) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT h.key, ip.key
		FROM entity_edge ed
		JOIN entity h  ON h.id = ed.src_id  AND h.type = 'host'
		JOIN entity ip ON ip.id = ed.dst_id AND ip.type = 'ip'
		WHERE ed.rel = 'resolves_to'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var host, ip string
		if err := rows.Scan(&host, &ip); err != nil {
			return err
		}
		fn(host, ip)
	}
	return rows.Err()
}

// ownIPs returns the set of IPs the host itself resolves to (its CDN addresses), to
// exclude them from the candidate origins.
func ownIPs(host string, rs resolveSet) map[string]struct{} {
	if ips, ok := rs.byHost[host]; ok {
		return ips
	}
	return map[string]struct{}{}
}

func add(m map[string]map[string]struct{}, key, val string) {
	if m[key] == nil {
		m[key] = map[string]struct{}{}
	}
	m[key][val] = struct{}{}
}

// registeredDomain approximates the registrable domain as the last two labels.
func registeredDomain(host string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(host, ".")), ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
