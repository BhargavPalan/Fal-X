package intel

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/store"
)

// osvEcosystems are the package ecosystems that can be synced from OSV. Each is its
// own source (osv-go, osv-pypi, ...), because the archives are large and an
// operator usually cares about a few of them.
var osvEcosystems = []string{"Go", "PyPI", "npm", "Maven", "crates.io", "RubyGems", "NuGet", "Packagist"}

const (
	osvBaseURL = "https://osv-vulnerabilities.storage.googleapis.com/"

	// maxOSVBytes caps one ecosystem archive as it comes off the wire, and
	// maxOSVRecord one advisory after it is unpacked.
	maxOSVBytes  int64 = 2 << 30
	maxOSVRecord       = 8 << 20
)

// Limits on text stored from an advisory. The identifier, package and purl columns
// are indexed or keyed, so their budgets leave room inside a btree entry.
const (
	maxOSVID      = 200
	maxOSVName    = 500
	maxOSVPURL    = 1000
	maxOSVSummary = 4000
	maxOSVDetails = 1 << 20
	osvBatchSize  = 1000
)

func osvSources() []Source {
	out := make([]Source, 0, len(osvEcosystems))
	for _, eco := range osvEcosystems {
		out = append(out, Source{
			Name:     "osv-" + strings.ToLower(eco),
			URL:      osvBaseURL + eco + "/all.zip",
			Group:    "osv",
			Optional: true,
			maxBytes: maxOSVBytes,
			apply:    applyOSV(eco),
		})
	}
	return out
}

// OSVAdvisory is one OSV record, reduced to what Fal-X keeps.
type OSVAdvisory struct {
	ID        string
	Modified  time.Time
	Published *time.Time
	Withdrawn *time.Time
	Aliases   []string
	Summary   string
	Details   string
	Affected  []OSVAffected
}

// OSVAffected is one package an advisory names. Ranges and Versions are kept as
// OSV states them.
type OSVAffected struct {
	Ecosystem string
	Name      string
	PURL      string
	Ranges    json.RawMessage
	Versions  []string
}

type osvRecord struct {
	ID        string   `json:"id"`
	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Withdrawn string   `json:"withdrawn"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl"`
		} `json:"package"`
		Ranges   json.RawMessage `json:"ranges"`
		Versions []string        `json:"versions"`
	} `json:"affected"`
}

// ParseOSV decodes one OSV advisory. A record with no id or no usable modified
// time is an error, so the caller can count it and move on.
func ParseOSV(r io.Reader) (*OSVAdvisory, error) {
	var rec osvRecord
	if err := json.NewDecoder(io.LimitReader(r, maxOSVRecord)).Decode(&rec); err != nil {
		return nil, fmt.Errorf("intel: decode OSV record: %w", err)
	}
	id := store.SafeText(strings.TrimSpace(rec.ID), maxOSVID)
	if id == "" {
		return nil, errors.New("intel: OSV record has no id")
	}
	modified, err := time.Parse(time.RFC3339, rec.Modified)
	if err != nil {
		return nil, fmt.Errorf("intel: OSV %s: bad modified time", id)
	}

	adv := &OSVAdvisory{
		ID: id, Modified: modified,
		Published: osvTime(rec.Published), Withdrawn: osvTime(rec.Withdrawn),
		Summary: store.SafeText(rec.Summary, maxOSVSummary),
		Details: store.SafeText(rec.Details, maxOSVDetails),
	}
	for _, a := range rec.Aliases {
		if a = store.SafeText(strings.TrimSpace(a), maxOSVID); a != "" {
			adv.Aliases = append(adv.Aliases, a)
		}
	}
	for _, a := range rec.Affected {
		adv.Affected = append(adv.Affected, OSVAffected{
			Ecosystem: store.SafeText(a.Package.Ecosystem, maxOSVName),
			Name:      store.SafeText(a.Package.Name, maxOSVName),
			PURL:      store.SafeText(a.Package.PURL, maxOSVPURL),
			Ranges:    jsonOrEmpty(a.Ranges),
			Versions:  a.Versions,
		})
	}
	return adv, nil
}

func osvTime(s string) *time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t
	}
	return nil
}

// noNUL replaces the JSON escape for U+0000, which jsonb refuses.
func noNUL(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte(`\u0000`), []byte(`�`))
}

// jsonOrEmpty returns raw when it is valid JSON that Postgres will accept, and an
// empty array otherwise.
func jsonOrEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || !json.Valid(raw) {
		return json.RawMessage("[]")
	}
	return noNUL(raw)
}

// ForEachOSV calls fn for every advisory in an OSV archive and returns how many
// entries were skipped as unreadable or repeated.
func ForEachOSV(zr *zip.Reader, fn func(*OSVAdvisory) error) (skipped int, err error) {
	seen := map[string]bool{}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || path.Ext(f.Name) != ".json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			skipped++
			continue
		}
		adv, perr := ParseOSV(rc)
		rc.Close()
		if perr != nil || seen[adv.ID] {
			skipped++
			continue
		}
		seen[adv.ID] = true
		if err := fn(adv); err != nil {
			return skipped, err
		}
	}
	return skipped, nil
}

// applyOSV returns the apply function for one ecosystem's archive.
//
// A zip has to be read from its end, so the body is spooled to a temporary file
// first. The ecosystem's advisories are replaced as a set inside the transaction,
// so one OSV has dropped stops being reported while the other ecosystems are left
// alone.
func applyOSV(ecosystem string) func(context.Context, *sql.Tx, io.Reader) (Applied, error) {
	return func(ctx context.Context, tx *sql.Tx, body io.Reader) (Applied, error) {
		tmp, err := os.CreateTemp("", "falx-osv-*.zip")
		if err != nil {
			return Applied{}, err
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		if _, err := io.Copy(tmp, body); err != nil {
			return Applied{}, fmt.Errorf("intel: download OSV %s: %w", ecosystem, err)
		}
		info, err := tmp.Stat()
		if err != nil {
			return Applied{}, err
		}
		zr, err := zip.NewReader(tmp, info.Size())
		if err != nil {
			return Applied{}, fmt.Errorf("intel: OSV %s archive is not a zip: %w", ecosystem, err)
		}

		if _, err := tx.ExecContext(ctx, "DELETE FROM osv_advisory WHERE ecosystem = $1", ecosystem); err != nil {
			return Applied{}, fmt.Errorf("intel: clear OSV %s: %w", ecosystem, err)
		}

		w := &osvWriter{ctx: ctx, tx: tx, ecosystem: ecosystem}
		skipped, err := ForEachOSV(zr, w.add)
		if err != nil {
			return Applied{}, err
		}
		if err := w.flush(); err != nil {
			return Applied{}, err
		}
		if w.count == 0 {
			return Applied{}, fmt.Errorf("intel: OSV %s archive held no advisories", ecosystem)
		}
		return Applied{Records: w.count, Skipped: skipped, Version: w.latest.UTC().Format(time.RFC3339)}, nil
	}
}

// osvWriter writes advisories in batches of a few statements each.
type osvWriter struct {
	ctx       context.Context
	tx        *sql.Tx
	ecosystem string
	pending   []*OSVAdvisory
	count     int
	latest    time.Time
}

func (w *osvWriter) add(a *OSVAdvisory) error {
	w.pending = append(w.pending, a)
	w.count++
	if a.Modified.After(w.latest) {
		w.latest = a.Modified
	}
	if len(w.pending) >= osvBatchSize {
		return w.flush()
	}
	return nil
}

// osvColumns are the parallel arrays one batch is sent as.
type osvColumns struct {
	ids, modified, published, withdrawn, summary, details []string

	affID, affEco, affName, affPURL, affRanges, affVersions []string
	affSeq                                                  []int32

	aliasID, aliasName, aliasCVE []string
	cves                         []string
}

func newOSVColumns(batch []*OSVAdvisory) *osvColumns {
	c := &osvColumns{}
	seenCVE := map[string]bool{}
	for _, a := range batch {
		c.ids = append(c.ids, a.ID)
		c.modified = append(c.modified, a.Modified.UTC().Format(time.RFC3339))
		c.published = append(c.published, timeText(a.Published))
		c.withdrawn = append(c.withdrawn, timeText(a.Withdrawn))
		c.summary = append(c.summary, a.Summary)
		c.details = append(c.details, a.Details)

		for i, x := range a.Affected {
			versions, _ := json.Marshal(x.Versions)
			if x.Versions == nil {
				versions = []byte("[]")
			}
			c.affID = append(c.affID, a.ID)
			c.affSeq = append(c.affSeq, int32(i))
			c.affEco = append(c.affEco, x.Ecosystem)
			c.affName = append(c.affName, x.Name)
			c.affPURL = append(c.affPURL, x.PURL)
			c.affRanges = append(c.affRanges, string(x.Ranges))
			c.affVersions = append(c.affVersions, string(noNUL(versions)))
		}

		var named []string
		for _, al := range a.Aliases {
			if id := strings.ToUpper(al); cveID.MatchString(id) {
				named = append(named, id)
				if !seenCVE[id] {
					seenCVE[id] = true
					c.cves = append(c.cves, id)
				}
			}
		}
		for _, cve := range named {
			for _, other := range append([]string{a.ID}, a.Aliases...) {
				if !cveID.MatchString(strings.ToUpper(other)) {
					c.aliasID = append(c.aliasID, a.ID)
					c.aliasName = append(c.aliasName, other)
					c.aliasCVE = append(c.aliasCVE, cve)
				}
			}
		}
	}
	return c
}

func (w *osvWriter) flush() error {
	if len(w.pending) == 0 {
		return nil
	}
	c := newOSVColumns(w.pending)
	w.pending = nil

	if _, err := w.tx.ExecContext(w.ctx, `
		INSERT INTO osv_advisory (ecosystem, osv_id, modified, published, withdrawn, summary, details)
		SELECT $1, t.id, t.modified::timestamptz, NULLIF(t.published, '')::timestamptz,
		       NULLIF(t.withdrawn, '')::timestamptz, t.summary, t.details
		FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[])
		     AS t(id, modified, published, withdrawn, summary, details)`,
		w.ecosystem, c.ids, c.modified, c.published, c.withdrawn, c.summary, c.details); err != nil {
		return fmt.Errorf("intel: store OSV advisories: %w", err)
	}
	if len(c.affID) > 0 {
		if _, err := w.tx.ExecContext(w.ctx, `
			INSERT INTO osv_affected (ecosystem, osv_id, seq, package_ecosystem, package_name, purl, ranges, versions)
			SELECT $1, t.id, t.seq, t.eco, t.name, t.purl, t.ranges::jsonb, t.versions::jsonb
			FROM unnest($2::text[], $3::int[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[])
			     AS t(id, seq, eco, name, purl, ranges, versions)`,
			w.ecosystem, c.affID, c.affSeq, c.affEco, c.affName, c.affPURL, c.affRanges, c.affVersions); err != nil {
			return fmt.Errorf("intel: store OSV packages: %w", err)
		}
	}
	if len(c.aliasID) > 0 {
		if err := ensureCVEs(w.ctx, w.tx, c.cves); err != nil {
			return err
		}
		if _, err := w.tx.ExecContext(w.ctx, `
			INSERT INTO cve_alias (alias, cve_id, ecosystem, osv_id)
			SELECT t.alias, t.cve, $1, t.id
			FROM unnest($2::text[], $3::text[], $4::text[]) AS t(id, alias, cve)
			ON CONFLICT DO NOTHING`,
			w.ecosystem, c.aliasID, c.aliasName, c.aliasCVE); err != nil {
			return fmt.Errorf("intel: store OSV aliases: %w", err)
		}
	}
	return nil
}

func timeText(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
