package intel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/store"
)

// NVDURL is the NVD CVE API, version 2.0.
const NVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// ErrNotInNVD means NVD has no record for the id: it may be reserved, rejected or
// not yet published. It is a normal answer, not a failure of the lookup.
var ErrNotInNVD = errors.New("intel: CVE not found in NVD")

// ErrRateLimited means NVD refused the request for going too fast. Keyless
// callers get five requests per thirty seconds.
var ErrRateLimited = errors.New("intel: NVD rate limit reached")

// NVDRecord is what Fal-X keeps from an NVD CVE entry.
type NVDRecord struct {
	CVE          string
	CVSSVersion  string
	CVSSScore    *float32
	CVSSSeverity string
	CVSSVector   string
	Description  string
	Published    *time.Time
	Modified     *time.Time
	Status       string
	CWEs         []string
	// Matches are the CPE configurations, in the order NVD lists them.
	Matches []CPEMatch
}

// nvdCVE is one CVE as NVD's 2.0 API and bulk feeds both state it.
type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Metrics map[string][]struct {
		Type     string `json:"type"`
		CVSSData struct {
			Version      string  `json:"version"`
			VectorString string  `json:"vectorString"`
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"metrics"`
	Configurations []struct {
		Operator string `json:"operator"`
		Nodes    []struct {
			Operator string `json:"operator"`
			Negate   bool   `json:"negate"`
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				MatchCriteriaID       string `json:"matchCriteriaId"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

// metricPreference lists NVD's metric families from newest to oldest. The newest
// available version is used, since that is the scale current guidance refers to.
var metricPreference = []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"}

// ParseNVD decodes an NVD API response for one CVE.
func ParseNVD(r io.Reader, id string) (*NVDRecord, error) {
	var resp nvdResponse
	if err := json.NewDecoder(io.LimitReader(r, 16<<20)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("intel: decode NVD response: %w", err)
	}
	if resp.TotalResults == 0 || len(resp.Vulnerabilities) == 0 {
		return nil, ErrNotInNVD
	}
	c := resp.Vulnerabilities[0].CVE
	if !strings.EqualFold(c.ID, id) {
		// An answer for a different CVE than the one asked about must never be
		// filed under the asked-for id.
		return nil, fmt.Errorf("intel: NVD answered for %q when asked about %q", c.ID, id)
	}

	return recordFrom(c), nil
}

// recordFrom reduces an NVD CVE to what Fal-X keeps.
func recordFrom(c nvdCVE) *NVDRecord {
	rec := &NVDRecord{
		CVE: strings.ToUpper(c.ID), Status: c.VulnStatus,
		Published: parseNVDTime(c.Published), Modified: parseNVDTime(c.LastModified),
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			rec.Description = d.Value
			break
		}
	}

	seen := map[string]bool{}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if d.Value != "" && !seen[d.Value] {
				seen[d.Value] = true
				rec.CWEs = append(rec.CWEs, d.Value)
			}
		}
	}

	for _, key := range metricPreference {
		ms := c.Metrics[key]
		if len(ms) == 0 {
			continue
		}
		pick := ms[0]
		for _, m := range ms {
			if m.Type == "Primary" { // NVD's own assessment beats a secondary source's
				pick = m
				break
			}
		}
		score := float32(pick.CVSSData.BaseScore)
		rec.CVSSScore = &score
		rec.CVSSVersion = pick.CVSSData.Version
		rec.CVSSSeverity = strings.ToUpper(pick.CVSSData.BaseSeverity)
		rec.CVSSVector = pick.CVSSData.VectorString
		break
	}

	for ci, cfg := range c.Configurations {
		for ni, node := range cfg.Nodes {
			for mi, m := range node.CPEMatch {
				part, vendor, product, version, err := ParseCPE(m.Criteria)
				if err != nil {
					continue
				}
				rec.Matches = append(rec.Matches, CPEMatch{
					ConfigSeq: ci, NodeSeq: ni, MatchSeq: mi,
					ConfigOperator: cfg.Operator, NodeOperator: node.Operator, Negate: node.Negate,
					Vulnerable: m.Vulnerable, Criteria: m.Criteria,
					Part: part, Vendor: vendor, Product: product, Version: version,
					StartIncluding: m.VersionStartIncluding, StartExcluding: m.VersionStartExcluding,
					EndIncluding: m.VersionEndIncluding, EndExcluding: m.VersionEndExcluding,
					MatchID: m.MatchCriteriaID,
				})
			}
		}
	}
	return rec
}

// parseNVDTime reads NVD's timestamps, which carry no zone and are UTC.
func parseNVDTime(s string) *time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// NVDOptions controls an enrichment run.
type NVDOptions struct {
	// BaseURL overrides the API endpoint; tests point it at a local server.
	BaseURL string
	// APIKey raises the rate limit. It is sent in a header and never logged.
	APIKey string
	// Client is the HTTP client. Nil uses one with a timeout.
	Client *http.Client
	// Delay is the pause between requests. Zero picks the polite default for the
	// presence or absence of a key.
	Delay time.Duration
	// MaxAge is how long a stored record counts as fresh. Zero means 7 days.
	MaxAge time.Duration
	// Force fetches even records that are fresh.
	Force bool
	// Progress is told about each id as it is handled. Optional.
	Progress func(id, outcome string)
}

// Outcomes reported to Progress and counted in NVDResult.
const (
	OutcomeFetched  = "fetched"
	OutcomeFresh    = "already fresh"
	OutcomeNotInNVD = "not in NVD"
)

// NVDResult says what an enrichment did.
type NVDResult struct {
	Fetched, Fresh, NotInNVD int
}

// NVDDelay is the pause between NVD requests that respects its published limits:
// five requests per thirty seconds without a key, fifty with one.
func NVDDelay(haveKey bool) time.Duration {
	if haveKey {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}

// EnrichNVD fetches NVD detail for each CVE and stores it.
//
// It stops at the first rate-limit refusal and returns what it had done, so a
// partial run is kept and the next run resumes from the records that are still
// stale. Each record is written in its own transaction for the same reason.
func EnrichNVD(ctx context.Context, db *store.DB, ids []string, opts NVDOptions) (NVDResult, error) {
	var res NVDResult
	if opts.BaseURL == "" {
		opts.BaseURL = NVDURL
	}
	if !strings.HasPrefix(opts.BaseURL, "https://") {
		return res, fmt.Errorf("intel: refusing non-https NVD endpoint %q", opts.BaseURL)
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 60 * time.Second}
	}
	if opts.Delay == 0 {
		opts.Delay = NVDDelay(opts.APIKey != "")
	}
	if opts.MaxAge == 0 {
		opts.MaxAge = 7 * 24 * time.Hour
	}
	say := func(id, outcome string) {
		if opts.Progress != nil {
			opts.Progress(id, outcome)
		}
	}

	requests := 0
	for _, raw := range ids {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if !cveID.MatchString(id) {
			continue
		}

		if !opts.Force {
			var age sql.NullTime
			err := db.SQL().QueryRowContext(ctx,
				"SELECT fetched_at FROM cve_nvd WHERE cve_id = $1", id).Scan(&age)
			if err == nil && age.Valid && time.Since(age.Time) < opts.MaxAge {
				res.Fresh++
				say(id, OutcomeFresh)
				continue
			}
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return res, fmt.Errorf("intel: check %s: %w", id, err)
			}
		}

		// Pace every request after the first.
		if requests > 0 {
			select {
			case <-ctx.Done():
				return res, ctx.Err()
			case <-time.After(opts.Delay):
			}
		}
		requests++

		rec, err := fetchNVD(ctx, opts, id)
		switch {
		case errors.Is(err, ErrNotInNVD):
			res.NotInNVD++
			say(id, OutcomeNotInNVD)
			continue
		case err != nil:
			return res, err
		}
		if err := storeNVD(ctx, db, rec); err != nil {
			return res, err
		}
		res.Fetched++
		say(id, OutcomeFetched)
	}
	return res, nil
}

func fetchNVD(ctx context.Context, opts NVDOptions, id string) (*NVDRecord, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		opts.BaseURL+"?cveId="+url.QueryEscape(id), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "fal-x")
	if opts.APIKey != "" {
		req.Header.Set("apiKey", opts.APIKey)
	}
	resp, err := opts.Client.Do(req)
	if err != nil {
		// The error text is the transport's, which does not include request
		// headers, so the key cannot leak through it.
		return nil, fmt.Errorf("intel: NVD request for %s: %w", id, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return ParseNVD(resp.Body, id)
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, fmt.Errorf("%w: HTTP %d for %s (set NVD_API_KEY for a higher limit)",
			ErrRateLimited, resp.StatusCode, id)
	default:
		return nil, fmt.Errorf("intel: NVD returned HTTP %d for %s", resp.StatusCode, id)
	}
}

func storeNVD(ctx context.Context, db *store.DB, r *NVDRecord) error {
	return db.InTx(ctx, func(tx *sql.Tx) error {
		return writeNVD(ctx, tx, []*NVDRecord{r})
	})
}
