// Package verify re-checks reported exposures against the live target, read-only, and
// records whether each still holds.
//
// An exposure finding is a candidate: a recon source saw evidence of a weakness but did
// not confirm it is still there. This pass re-requests that evidence — the exposed file,
// the dangling CNAME — with no intrusive action, and writes a `verification` fact
// (confirmed, refuted or inconclusive) with the evidence behind it. A confirmed finding
// is re-asserted at high confidence so it outranks an unverified one; a refuted one is
// left marked stale. It never attempts a claim, a write or a credential submission:
// confirming is reading.
package verify

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/exposure"
	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources/native"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// source names this pass as the provenance of the facts it writes.
const source = "verify"

// Checker performs the read-only network checks a verifier needs. It is an interface so
// Run is tested without the live network.
type Checker interface {
	// Get fetches a URL read-only. reached is false when nothing answered.
	Get(ctx context.Context, rawURL string) (body []byte, status int, reached bool)
	// Resolves reports whether a host name resolves. It returns (false, nil) for a clean
	// NXDOMAIN and a non-nil error for any other failure.
	Resolves(ctx context.Context, host string) (bool, error)
}

// Summary counts the verdicts a run produced.
type Summary struct {
	Confirmed    int
	Refuted      int
	Inconclusive int
}

// Run verifies the tenant's reported exposures. Reads, network checks and writes are
// separated so a slow probe never holds a database transaction open.
func Run(ctx context.Context, db *store.DB, orgID int64, chk Checker) (Summary, error) {
	var sum Summary
	cands, err := readCandidates(ctx, db)
	if err != nil {
		return sum, err
	}
	results := make([]result, 0, len(cands))
	for _, c := range cands {
		v, ev := c.check(ctx, chk)
		switch v {
		case Confirmed:
			sum.Confirmed++
		case Refuted:
			sum.Refuted++
		default:
			sum.Inconclusive++
		}
		results = append(results, result{cand: c, verdict: v, evidence: ev})
	}
	return sum, writeResults(ctx, db, results)
}

// candidate is one reported exposure to re-check.
type candidate interface {
	check(ctx context.Context, chk Checker) (Verdict, string)
	entityID() int64
	// confirmedFinding is the finding and exposure class to re-assert at high confidence
	// when the verdict is confirmed, so a confirmed exposure outranks an unverified one.
	confirmedFinding() (value, class string)
	label() string
}

// exposedFileCand is a served sensitive file to re-request by its URL.
type exposedFileCand struct {
	id           int64
	rawURL       string
	signature    string
	class        string
	findingValue string
}

func (c exposedFileCand) entityID() int64 { return c.id }
func (c exposedFileCand) label() string   { return c.class }
func (c exposedFileCand) confirmedFinding() (string, string) {
	return c.findingValue + " (verified)", c.class
}
func (c exposedFileCand) check(ctx context.Context, chk Checker) (Verdict, string) {
	// Soft-404 guard: a host that answers 200 to a random path matches any weak signature,
	// so confirming from a body check would be a false positive. This mirrors the guard the
	// original probe (native.ExposedFiles) applies before it records a hit at all.
	_, rndStatus, rndReached := chk.Get(ctx, baseOf(c.rawURL)+"/falx-nonexistent-9f3a2b1c")
	catchAll := rndReached && rndStatus == 200
	body, status, reached := chk.Get(ctx, c.rawURL)
	return verifyExposedFile(reached, catchAll, status, body, c.signature)
}

// takeoverCand is a host whose CNAME points at a takeover-prone service.
type takeoverCand struct {
	id       int64
	host     string
	cname    string
	provider string
}

func (c takeoverCand) entityID() int64 { return c.id }
func (c takeoverCand) label() string   { return "takeover" }
func (c takeoverCand) confirmedFinding() (string, string) {
	return "critical subdomain-takeover-confirmed " + c.provider, "takeover"
}
func (c takeoverCand) check(ctx context.Context, chk Checker) (Verdict, string) {
	stillFingerprinted := exposure.TakeoverProvider(c.cname) != ""
	resolves, err := chk.Resolves(ctx, strings.TrimSuffix(c.cname, "."))
	return verifyTakeover(stillFingerprinted, resolves, err)
}

// result pairs a candidate with its verdict.
type result struct {
	cand     candidate
	verdict  Verdict
	evidence string
}

// baseOf returns the scheme://host of a URL, for probing a sibling path on the same host.
func baseOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}

// readCandidates collects the exposures worth re-checking in one transaction, which is
// closed before any network call.
func readCandidates(ctx context.Context, db *store.DB) ([]candidate, error) {
	var cands []candidate
	err := db.InTx(ctx, func(tx *sql.Tx) error {
		files, err := readExposedFiles(ctx, tx)
		if err != nil {
			return err
		}
		takeovers, err := readTakeovers(ctx, tx)
		if err != nil {
			return err
		}
		cands = append(cands, files...)
		cands = append(cands, takeovers...)
		return nil
	})
	return cands, err
}

// readExposedFiles finds URL entities whose path is a known sensitive file, each the
// evidence of an exposed-file finding.
func readExposedFiles(ctx context.Context, tx *sql.Tx) ([]candidate, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id, key FROM entity WHERE type = 'url'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []candidate
	for rows.Next() {
		var id int64
		var rawURL string
		if err := rows.Scan(&id, &rawURL); err != nil {
			return nil, err
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		sig, class, value, ok := native.SensitiveFileSignature(u.Path)
		if !ok {
			continue
		}
		out = append(out, exposedFileCand{id: id, rawURL: rawURL, signature: sig, class: class, findingValue: value})
	}
	return out, rows.Err()
}

// readTakeovers finds hosts whose CNAME still names a takeover-prone service.
func readTakeovers(ctx context.Context, tx *sql.Tx) ([]candidate, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT e.id, e.key, f.value
		FROM entity_fact f JOIN entity e ON e.id = f.entity_id
		WHERE e.type = 'host' AND f.key = 'cname'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []candidate
	for rows.Next() {
		var id int64
		var host, cname string
		if err := rows.Scan(&id, &host, &cname); err != nil {
			return nil, err
		}
		if p := exposure.TakeoverProvider(cname); p != "" {
			out = append(out, takeoverCand{id: id, host: host, cname: cname, provider: p})
		}
	}
	return out, rows.Err()
}

// writeResults records each verdict in one transaction. A confirmation also re-asserts
// the finding at high confidence so it is ranked above an unverified one.
func writeResults(ctx context.Context, db *store.DB, results []result) error {
	if len(results) == 0 {
		return nil
	}
	return db.InTx(ctx, func(tx *sql.Tx) error {
		for _, r := range results {
			ref := graph.Ref(r.cand.entityID())
			value := fmt.Sprintf("%s %s — %s", r.verdict, r.cand.label(), r.evidence)
			if err := graph.AddFact(ctx, tx, ref, "verification", value, source, false, r.verdict.confidence(), 0); err != nil {
				return err
			}
			if r.verdict != Confirmed {
				continue
			}
			fv, class := r.cand.confirmedFinding()
			if err := graph.AddFact(ctx, tx, ref, "finding", fv, source, false, 0.95, 0); err != nil {
				return err
			}
			if err := graph.AddFact(ctx, tx, ref, "exposure", class, source, false, 0.95, 0); err != nil {
				return err
			}
		}
		return nil
	})
}
