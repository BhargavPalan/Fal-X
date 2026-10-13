// Package exposure turns the facts the recon sources collected into findings: the
// classes of weakness that are visible in the graph without any intrusive action.
//
// It runs as a pass over the graph after collection and correlation, reading facts
// and writing a finding (with a severity the prioritiser ranks) and an exposure class
// (for the report to group by) back onto the entity that carries the evidence. A
// finding here is a candidate: it says the evidence is present, not that exploitation
// was attempted. Confirmation is the job of a separate, read-only verification stage.
package exposure

import (
	"context"
	"database/sql"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// Run writes exposure findings for the tenant. The transaction is opened for the
// organization, so row-level security scopes every read and write.
func Run(ctx context.Context, db *store.DB, orgID int64) error {
	return db.InTx(ctx, func(tx *sql.Tx) error {
		if err := flagCertificateWeaknesses(ctx, tx); err != nil {
			return err
		}
		return flagTakeoverCandidates(ctx, tx)
	})
}

// finding records a finding and its exposure class on an entity. Both writes are
// upserts, so re-running the pass does not duplicate them.
func finding(ctx context.Context, tx *sql.Tx, id int64, class, value string, confidence float64) error {
	if err := graph.AddFact(ctx, tx, graph.Ref(id), "finding", value, "exposure", true, confidence, 0); err != nil {
		return err
	}
	return graph.AddFact(ctx, tx, graph.Ref(id), "exposure", class, "exposure", true, confidence, 0)
}

// hit is one entity to flag with a finding.
type hit struct {
	id         int64
	class, val string
	conf       float64
}

// flagCertificateWeaknesses turns the TLS posture facts into findings: a certificate
// that is expired, self-signed, or signed with a broken algorithm. The rows are read
// and the connection released before any finding is written, because writing on the
// same transaction while a result set is open is not allowed.
func flagCertificateWeaknesses(ctx context.Context, tx *sql.Tx) error {
	hits, err := certificateHits(ctx, tx)
	if err != nil {
		return err
	}
	return writeHits(ctx, tx, hits)
}

func certificateHits(ctx context.Context, tx *sql.Tx) ([]hit, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT e.id, f.key, f.value
		FROM entity_fact f JOIN entity e ON e.id = f.entity_id
		WHERE e.type = 'certificate' AND f.key IN ('expired', 'self_signed', 'weak_signature')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hits []hit
	for rows.Next() {
		var id int64
		var key, val string
		if err := rows.Scan(&id, &key, &val); err != nil {
			return nil, err
		}
		switch key {
		case "expired":
			hits = append(hits, hit{id, "expired_cert", "medium expired-certificate", 1.0})
		case "self_signed":
			hits = append(hits, hit{id, "self_signed_cert", "low self-signed-certificate", 0.9})
		case "weak_signature":
			hits = append(hits, hit{id, "weak_cert", "medium weak-certificate-signature " + val, 0.9})
		}
	}
	return hits, rows.Err()
}

// flagTakeoverCandidates flags a host whose CNAME points at a service known to be
// claimable, the signature of a subdomain takeover. It is a candidate: the pass does
// not attempt a claim, only reports that the dangling target is present.
func flagTakeoverCandidates(ctx context.Context, tx *sql.Tx) error {
	hits, err := takeoverHits(ctx, tx)
	if err != nil {
		return err
	}
	return writeHits(ctx, tx, hits)
}

func takeoverHits(ctx context.Context, tx *sql.Tx) ([]hit, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT e.id, f.value
		FROM entity_fact f JOIN entity e ON e.id = f.entity_id
		WHERE e.type = 'host' AND f.key = 'cname'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hits []hit
	for rows.Next() {
		var id int64
		var cname string
		if err := rows.Scan(&id, &cname); err != nil {
			return nil, err
		}
		if p := TakeoverProvider(cname); p != "" {
			hits = append(hits, hit{id, "takeover", "high subdomain-takeover " + p, 0.7})
		}
	}
	return hits, rows.Err()
}

// writeHits records each collected finding. It runs after the result set is closed.
func writeHits(ctx context.Context, tx *sql.Tx, hits []hit) error {
	for _, h := range hits {
		if err := finding(ctx, tx, h.id, h.class, h.val, h.conf); err != nil {
			return err
		}
	}
	return nil
}

// takeoverFingerprints are CNAME suffixes for services where an unclaimed target can
// be registered by an attacker, drawn from the can-i-take-over-xyz catalogue.
var takeoverFingerprints = map[string]string{
	"github.io":             "GitHub Pages",
	"herokuapp.com":         "Heroku",
	"herokudns.com":         "Heroku",
	"s3.amazonaws.com":      "Amazon S3",
	"s3-website":            "Amazon S3",
	"azurewebsites.net":     "Azure App Service",
	"cloudapp.net":          "Azure",
	"cloudapp.azure.com":    "Azure",
	"trafficmanager.net":    "Azure Traffic Manager",
	"blob.core.windows.net": "Azure Blob Storage",
	"ghost.io":              "Ghost",
	"surge.sh":              "Surge",
	"bitbucket.io":          "Bitbucket",
	"pantheonsite.io":       "Pantheon",
	"zendesk.com":           "Zendesk",
	"statuspage.io":         "Statuspage",
	"uservoice.com":         "UserVoice",
	"helpscoutdocs.com":     "Help Scout",
	"readme.io":             "Readme",
	"readthedocs.io":        "Read the Docs",
	"netlify.app":           "Netlify",
	"wordpress.com":         "WordPress",
	"fastly.net":            "Fastly",
	"cargocollective.com":   "Cargo",
	"wpengine.com":          "WP Engine",
	"launchrock.com":        "LaunchRock",
	"myshopify.com":         "Shopify",
	"tumblr.com":            "Tumblr",
	"unbouncepages.com":     "Unbounce",
	"desk.com":              "Desk",
	"teamwork.com":          "Teamwork",
}

// TakeoverProvider returns the service a CNAME target belongs to when it is a known
// takeover-prone platform, or an empty string.
func TakeoverProvider(cname string) string {
	c := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
	for suffix, provider := range takeoverFingerprints {
		if c == suffix || strings.HasSuffix(c, "."+suffix) || strings.Contains(c, suffix) {
			return provider
		}
	}
	return ""
}
