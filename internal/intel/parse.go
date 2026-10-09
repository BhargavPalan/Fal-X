// Package intel keeps the vulnerability intelligence Fal-X correlates assets
// against: the CVE id as a spine, and the public feeds that say something about
// each id.
//
// The parsers in this file are pure. They take a reader and return values, so
// they are tested against fixtures with no network and no database. Fetching and
// storing live in sync.go and nvd.go.
package intel

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/util"
)

// cveID is the shape the database also enforces. A feed row that does not match
// is counted and skipped rather than failing the whole sync: one malformed row in
// a hundred thousand must not cost the other ninety-nine thousand nine hundred.
var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// cveInText finds CVE ids inside free text such as a finding's value.
var cveInText = regexp.MustCompile(`(?i)CVE-[0-9]{4}-[0-9]{4,}`)

// CVEsIn returns the distinct CVE ids mentioned in text, upper-cased, in the
// order they first appear.
func CVEsIn(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range cveInText.FindAllString(text, -1) {
		id := strings.ToUpper(m)
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// KEVEntry is one CISA Known Exploited Vulnerabilities record.
type KEVEntry struct {
	CVE              string
	VendorProject    string
	Product          string
	Name             string
	DateAdded        time.Time
	ShortDescription string
	RequiredAction   string
	DueDate          *time.Time
	KnownRansomware  bool
	Notes            string
	CWEs             []string
}

// KEVCatalog is a parsed KEV feed.
type KEVCatalog struct {
	// Version is the catalogue's own version string, which is what the watermark
	// records.
	Version string
	Entries []KEVEntry
	// Skipped counts rows dropped for an invalid CVE id or date.
	Skipped int
}

type kevFile struct {
	CatalogVersion  string `json:"catalogVersion"`
	Vulnerabilities []struct {
		CVEID                      string   `json:"cveID"`
		VendorProject              string   `json:"vendorProject"`
		Product                    string   `json:"product"`
		VulnerabilityName          string   `json:"vulnerabilityName"`
		DateAdded                  string   `json:"dateAdded"`
		ShortDescription           string   `json:"shortDescription"`
		RequiredAction             string   `json:"requiredAction"`
		DueDate                    string   `json:"dueDate"`
		KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
		Notes                      string   `json:"notes"`
		CWEs                       []string `json:"cwes"`
	} `json:"vulnerabilities"`
}

// ParseKEV decodes the CISA KEV JSON feed.
func ParseKEV(r io.Reader) (*KEVCatalog, error) {
	var f kevFile
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, fmt.Errorf("intel: decode KEV feed: %w", err)
	}
	if len(f.Vulnerabilities) == 0 {
		// An empty catalogue is far more likely to be a wrong or truncated
		// response than the real state of the world, and storing it would look
		// like a clean sync.
		return nil, errors.New("intel: KEV feed held no vulnerabilities")
	}

	c := &KEVCatalog{Version: f.CatalogVersion}
	for _, v := range f.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVEID))
		added, err := time.Parse(util.DateOnly, v.DateAdded)
		if !cveID.MatchString(id) || err != nil {
			c.Skipped++
			continue
		}
		e := KEVEntry{
			CVE: id, VendorProject: strings.TrimSpace(v.VendorProject),
			Product: strings.TrimSpace(v.Product), Name: strings.TrimSpace(v.VulnerabilityName),
			DateAdded: added, ShortDescription: v.ShortDescription,
			RequiredAction: v.RequiredAction, Notes: v.Notes, CWEs: v.CWEs,
			KnownRansomware: strings.EqualFold(v.KnownRansomwareCampaignUse, "Known"),
		}
		if d, err := time.Parse(util.DateOnly, v.DueDate); err == nil {
			e.DueDate = &d
		}
		c.Entries = append(c.Entries, e)
	}
	if len(c.Entries) == 0 {
		return nil, errors.New("intel: KEV feed held no usable rows")
	}
	return c, nil
}

// EPSSScore is one EPSS probability.
type EPSSScore struct {
	CVE        string
	Score      float32
	Percentile float32
}

// EPSSFile is a parsed EPSS feed.
type EPSSFile struct {
	ModelVersion string
	ScoreDate    time.Time
	Scores       []EPSSScore
	Skipped      int
}

// maxEPSSBytes caps the decompressed feed. The real one is about 13 MiB; the cap
// only stops a wrong URL or a decompression bomb from filling memory.
var maxEPSSBytes int64 = 256 << 20

// ParseEPSS decodes the gzipped EPSS CSV, whose first line is metadata:
//
//	#model_version:v2026.06.15,score_date:2026-10-08T12:00:21Z
//	cve,epss,percentile
//	CVE-1999-0001,0.03351,0.88354
func ParseEPSS(r io.Reader) (*EPSSFile, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("intel: EPSS feed is not gzip: %w", err)
	}
	defer zr.Close()

	sc := bufio.NewScanner(&capReader{r: zr, left: maxEPSSBytes})
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	out := &EPSSFile{}
	sawHeader := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "#"):
			for _, kv := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
				k, v, ok := strings.Cut(kv, ":")
				if !ok {
					continue
				}
				switch strings.TrimSpace(k) {
				case "model_version":
					out.ModelVersion = strings.TrimSpace(v)
				case "score_date":
					if t, err := time.Parse(time.RFC3339, strings.TrimSpace(v)); err == nil {
						out.ScoreDate = t
					}
				}
			}
			continue
		case !sawHeader:
			if !strings.HasPrefix(strings.ToLower(line), "cve,") {
				return nil, fmt.Errorf("intel: EPSS header is %q, want cve,epss,percentile", line)
			}
			sawHeader = true
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			out.Skipped++
			continue
		}
		id := strings.ToUpper(strings.TrimSpace(parts[0]))
		score, e1 := strconv.ParseFloat(parts[1], 32)
		pct, e2 := strconv.ParseFloat(parts[2], 32)
		if !cveID.MatchString(id) || e1 != nil || e2 != nil ||
			score < 0 || score > 1 || pct < 0 || pct > 1 {
			out.Skipped++
			continue
		}
		out.Scores = append(out.Scores, EPSSScore{CVE: id, Score: float32(score), Percentile: float32(pct)})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("intel: read EPSS feed: %w", err)
	}
	if !sawHeader || len(out.Scores) == 0 {
		return nil, errors.New("intel: EPSS feed held no scores")
	}
	if out.ScoreDate.IsZero() {
		// No score date in the metadata: use today rather than store a zero date
		// that would read as a score from the year 1.
		out.ScoreDate = time.Now().UTC()
	}
	return out, nil
}
