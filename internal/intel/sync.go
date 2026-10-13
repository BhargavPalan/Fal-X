package intel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/store"
)

// Source is one intelligence feed.
type Source struct {
	// Name is the key used on the command line and in source_watermark.
	Name string
	// URL is the feed. It must be https.
	URL string
	// Group names a family of sources that can be selected together, such as osv.
	Group string
	// Optional keeps the source out of a default sync, for feeds that are large or
	// that most operators do not need.
	Optional bool
	// maxBytes caps the download; zero means maxFeedBytes.
	maxBytes int64
	// anySize switches off the shrink guard, for a feed whose size legitimately
	// varies from one sync to the next.
	anySize bool
	// apply parses the body and writes it, returning the record count, the
	// version to record, and how many rows were skipped as malformed.
	apply func(ctx context.Context, tx *sql.Tx, body io.Reader) (applied Applied, err error)
}

// Applied is what writing one feed produced.
type Applied struct {
	Records int
	Skipped int
	Version string
}

// Sources are the feeds Fal-X can sync. None needs an account or a key.
var Sources = append([]Source{
	{
		Name:  "kev",
		URL:   "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		apply: applyKEV,
	},
	{
		Name:  "epss",
		URL:   "https://epss.cyentia.com/epss_scores-current.csv.gz",
		apply: applyEPSS,
	},
}, append(osvSources(), nvdSources()...)...)

// maxFeedBytes caps one download as it comes off the wire.
var maxFeedBytes int64 = 64 << 20

func (s Source) limit() int64 {
	if s.maxBytes > 0 {
		return s.maxBytes
	}
	return maxFeedBytes
}

// batchSize is how many rows go into one INSERT. Large enough that the real EPSS
// feed (about 385,000 rows) is a hundred statements, small enough to stay well
// under the driver's parameter limits.
const batchSize = 5000

// Result describes one source's sync.
type Result struct {
	Source string
	// NotModified is true when the server said nothing had changed and nothing
	// was downloaded.
	NotModified bool
	Records     int
	Skipped     int
	Version     string
	Took        time.Duration
}

// Options controls Sync.
type Options struct {
	// Force downloads and rewrites even when the server says nothing changed.
	Force bool
	// AllowShrink accepts a feed that holds far fewer records than the last good
	// sync, which is otherwise refused.
	AllowShrink bool
	// Client is the HTTP client. Nil uses one with a timeout.
	Client *http.Client
}

// Lookup returns the named sources. A group name such as osv selects all of its
// members. With no names it returns every source that is not Optional.
func Lookup(names []string) ([]Source, error) {
	var out []Source
	if len(names) == 0 {
		for _, s := range Sources {
			if !s.Optional {
				out = append(out, s)
			}
		}
		return out, nil
	}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		before := len(out)
		for _, s := range Sources {
			if s.Name == n || s.Group == n {
				out = append(out, s)
			}
		}
		if len(out) == before {
			return nil, fmt.Errorf("unknown intelligence source %q (known: %s)", n, sourceNames())
		}
	}
	return out, nil
}

func sourceNames() string {
	n := make([]string, 0, len(Sources)+1)
	groups := map[string]bool{}
	for _, s := range Sources {
		n = append(n, s.Name)
		if s.Group != "" && !groups[s.Group] {
			groups[s.Group] = true
			n = append(n, s.Group)
		}
	}
	return strings.Join(n, ", ")
}

// Sync fetches and stores one source.
//
// It is conditional: it sends the validators saved from the last sync, and a
// "not modified" answer ends it without a download. It is also atomic: the data
// and the watermark are written in one transaction, so a failed sync leaves the
// previous data and the previous watermark, and the next attempt starts clean.
func Sync(ctx context.Context, db *store.DB, src Source, opts Options) (Result, error) {
	start := time.Now()
	res := Result{Source: src.Name}

	if !strings.HasPrefix(src.URL, "https://") {
		return res, fmt.Errorf("intel: refusing non-https source %q", src.URL)
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Minute}
	}

	// The previous record count feeds the shrink guard below, so it is read even
	// when Force is set: forcing a download is not permission to accept a broken one.
	var previous int
	var etag, lastMod string
	err := db.SQL().QueryRowContext(ctx,
		"SELECT records, etag, last_modified FROM source_watermark WHERE source = $1", src.Name).
		Scan(&previous, &etag, &lastMod)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return res, fmt.Errorf("intel: read watermark: %w", err)
	}
	if opts.Force {
		etag, lastMod = "", ""
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, http.NoBody)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", "fal-x")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}
	resp, err := client.Do(req)
	if err != nil {
		return res, fmt.Errorf("intel: fetch %s: %w", src.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		res.Took = time.Since(start)
		// A 304 is only valid as the answer to the conditional request we send when a
		// prior watermark gave us a validator. Record that we checked so `intel status`
		// shows the sync is current — but if there is no watermark row to touch, the
		// server answered 304 to an unconditional request and no data was ever stored.
		// Report that rather than claim an up-to-date sync that never happened.
		out, err := db.SQL().ExecContext(ctx,
			"UPDATE source_watermark SET synced_at = now() WHERE source = $1", src.Name)
		if err != nil {
			return res, err
		}
		if n, _ := out.RowsAffected(); n == 0 {
			return res, fmt.Errorf("intel: %s returned HTTP 304 but no prior sync exists; "+
				"sync again with --force to download it", src.Name)
		}
		res.NotModified = true
		return res, nil
	}
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("intel: fetch %s: HTTP %d", src.Name, resp.StatusCode)
	}

	err = db.InTx(ctx, func(tx *sql.Tx) error {
		a, err := src.apply(ctx, tx, &capReader{r: resp.Body, left: src.limit()})
		if err != nil {
			return err
		}
		// A feed that suddenly holds far fewer records than the last good one is
		// more likely a partial or wrong response than the real state of the
		// world. Returning an error rolls the whole sync back, data and watermark.
		if !opts.AllowShrink && !src.anySize && previous > 0 && a.Records*2 < previous {
			return fmt.Errorf("intel: %s feed shrank from %d to %d records; refusing it "+
				"(if that is real, sync again with --allow-shrink)", src.Name, previous, a.Records)
		}
		res.Records, res.Skipped, res.Version = a.Records, a.Skipped, a.Version
		_, err = tx.ExecContext(ctx, `
			INSERT INTO source_watermark (source, etag, last_modified, version, records, synced_at)
			VALUES ($1, $2, $3, $4, $5, now())
			ON CONFLICT (source) DO UPDATE SET
				etag = EXCLUDED.etag, last_modified = EXCLUDED.last_modified,
				version = EXCLUDED.version, records = EXCLUDED.records, synced_at = now()`,
			src.Name, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), a.Version, a.Records)
		return err
	})
	res.Took = time.Since(start)
	return res, err
}

// ensureCVEs makes sure every id has a cve row, in batches.
func ensureCVEs(ctx context.Context, tx *sql.Tx, ids []string) error {
	for chunk := range slices.Chunk(ids, batchSize) {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO cve (cve_id) SELECT unnest($1::text[])
			ON CONFLICT (cve_id) DO UPDATE SET last_seen_at = now()`, chunk); err != nil {
			return fmt.Errorf("intel: upsert cve ids: %w", err)
		}
	}
	return nil
}

func applyKEV(ctx context.Context, tx *sql.Tx, body io.Reader) (Applied, error) {
	cat, err := ParseKEV(body)
	if err != nil {
		return Applied{}, err
	}
	ids := make([]string, len(cat.Entries))
	for i, e := range cat.Entries {
		ids[i] = e.CVE
	}
	if err := ensureCVEs(ctx, tx, ids); err != nil {
		return Applied{}, err
	}
	// Entries CISA has withdrawn must go. Upserting alone leaves them forever, and
	// a withdrawn entry that still reads as "known exploited" makes the
	// prioritizer say Act about a CVE that is no longer on the list. But an EMPTY
	// parse is never a reason to purge the whole table: `cve_id <> ALL('{}')` is true
	// for every row, so a malformed or truncated feed that yielded no entries would
	// wipe all KEV data. Only prune when the feed actually carried entries.
	if len(ids) > 0 {
		if _, err := tx.ExecContext(ctx,
			"DELETE FROM cve_kev_cisa WHERE cve_id <> ALL($1::text[])", ids); err != nil {
			return Applied{}, fmt.Errorf("intel: remove withdrawn KEV entries: %w", err)
		}
	}
	for _, e := range cat.Entries {
		cwes := e.CWEs
		if cwes == nil {
			cwes = []string{}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO cve_kev_cisa
				(cve_id, vendor_project, product, vulnerability_name, date_added,
				 short_description, required_action, due_date, known_ransomware, notes, cwes)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (cve_id) DO UPDATE SET
				vendor_project = EXCLUDED.vendor_project, product = EXCLUDED.product,
				vulnerability_name = EXCLUDED.vulnerability_name, date_added = EXCLUDED.date_added,
				short_description = EXCLUDED.short_description, required_action = EXCLUDED.required_action,
				due_date = EXCLUDED.due_date, known_ransomware = EXCLUDED.known_ransomware,
				notes = EXCLUDED.notes, cwes = EXCLUDED.cwes`,
			e.CVE, e.VendorProject, e.Product, e.Name, e.DateAdded, e.ShortDescription,
			e.RequiredAction, e.DueDate, e.KnownRansomware, e.Notes, cwes); err != nil {
			return Applied{}, fmt.Errorf("intel: store KEV %s: %w", e.CVE, err)
		}
	}
	return Applied{Records: len(cat.Entries), Skipped: cat.Skipped, Version: cat.Version}, nil
}

func applyEPSS(ctx context.Context, tx *sql.Tx, body io.Reader) (Applied, error) {
	f, err := ParseEPSS(body)
	if err != nil {
		return Applied{}, err
	}
	ids := make([]string, len(f.Scores))
	for i, s := range f.Scores {
		ids[i] = s.CVE
	}
	if err := ensureCVEs(ctx, tx, ids); err != nil {
		return Applied{}, err
	}
	// The scores are one scoring run. A CVE the new run does not list must not keep
	// an old probability that reads as current, so the set is replaced, inside this
	// transaction so readers never see it empty.
	if _, err := tx.ExecContext(ctx, "DELETE FROM cve_epss"); err != nil {
		return Applied{}, fmt.Errorf("intel: clear old EPSS scores: %w", err)
	}
	for chunk := range slices.Chunk(f.Scores, batchSize) {
		cves := make([]string, len(chunk))
		scores := make([]float32, len(chunk))
		pcts := make([]float32, len(chunk))
		for j, s := range chunk {
			cves[j], scores[j], pcts[j] = s.CVE, s.Score, s.Percentile
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO cve_epss (cve_id, epss, percentile, score_date, model_version)
			SELECT t.cve_id, t.epss, t.percentile, $4::date, $5
			FROM unnest($1::text[], $2::real[], $3::real[]) AS t(cve_id, epss, percentile)
			ON CONFLICT (cve_id) DO UPDATE SET
				epss = EXCLUDED.epss, percentile = EXCLUDED.percentile,
				score_date = EXCLUDED.score_date, model_version = EXCLUDED.model_version`,
			cves, scores, pcts, f.ScoreDate, f.ModelVersion); err != nil {
			return Applied{}, fmt.Errorf("intel: store EPSS batch: %w", err)
		}
	}
	return Applied{Records: len(f.Scores), Skipped: f.Skipped, Version: f.ModelVersion}, nil
}
