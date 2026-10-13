package intel

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/store"
)

const (
	nvdFeedBase = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"

	// maxNVDWireBytes caps one compressed feed as it comes off the wire, and
	// maxNVDJSONBytes the same feed after decompression. The largest year is about
	// 25 MiB compressed and ten times that expanded.
	maxNVDWireBytes int64 = 1 << 30
	maxNVDJSONBytes int64 = 4 << 30

	nvdFirstYear = 2002

	// Rows per statement. A CVE can carry hundreds of CPE entries, so a batch is
	// closed by either count.
	nvdBatchCVEs    = 500
	nvdBatchMatches = 20000
)

// nvdSources are the bulk feeds: one per year of publication, which together hold
// the whole corpus, plus the feed of everything changed in the last eight days.
// They are opt-in because the full set is several hundred megabytes.
func nvdSources() []Source {
	var out []Source
	for y := nvdFirstYear; y <= time.Now().Year(); y++ {
		out = append(out, nvdSource("nvd-"+strconv.Itoa(y), strconv.Itoa(y), false))
	}
	return append(out, nvdSource("nvd-modified", "modified", true))
}

func nvdSource(name, file string, anySize bool) Source {
	return Source{
		Name: name, URL: nvdFeedBase + file + ".json.gz", Group: "nvd", Optional: true,
		maxBytes: maxNVDWireBytes, anySize: anySize, apply: applyNVDFeed,
	}
}

// NVDFeedInfo is what ParseNVDFeed learned besides the CVEs.
type NVDFeedInfo struct {
	// Timestamp is when NVD generated the feed.
	Timestamp string
	// Records is how many CVEs were passed to the callback.
	Records int
	// Skipped counts entries with an unusable CVE id.
	Skipped int
}

// ParseNVDFeed streams an NVD 2.0 feed and calls fn for each CVE, so a feed that
// expands to gigabytes is never held in memory.
func ParseNVDFeed(r io.Reader, fn func(*NVDRecord) error) (NVDFeedInfo, error) {
	var info NVDFeedInfo
	dec := json.NewDecoder(r)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return info, errors.New("intel: NVD feed is not a JSON object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return info, fmt.Errorf("intel: read NVD feed: %w", err)
		}
		key, _ := keyTok.(string)
		switch key {
		case "timestamp":
			if err := dec.Decode(&info.Timestamp); err != nil {
				return info, fmt.Errorf("intel: read NVD feed: %w", err)
			}
		case "vulnerabilities":
			if err := streamVulnerabilities(dec, fn, &info); err != nil {
				return info, err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return info, fmt.Errorf("intel: read NVD feed: %w", err)
			}
		}
	}
	return info, nil
}

func streamVulnerabilities(dec *json.Decoder, fn func(*NVDRecord) error, info *NVDFeedInfo) error {
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return errors.New("intel: NVD feed has no vulnerability list")
	}
	for dec.More() {
		var item struct {
			CVE nvdCVE `json:"cve"`
		}
		if err := dec.Decode(&item); err != nil {
			return fmt.Errorf("intel: read NVD feed: %w", err)
		}
		if !cveID.MatchString(strings.ToUpper(item.CVE.ID)) {
			info.Skipped++
			continue
		}
		info.Records++
		if err := fn(recordFrom(item.CVE)); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

// applyNVDFeed stores a gzipped NVD feed. It only adds and updates: NVD does not
// delete CVEs, and a CVE that stays in the corpus is replaced wholesale, its CPE
// configurations included, so a narrowed configuration does not leave old rows.
func applyNVDFeed(ctx context.Context, tx *sql.Tx, body io.Reader) (Applied, error) {
	zr, err := gzip.NewReader(body)
	if err != nil {
		return Applied{}, fmt.Errorf("intel: NVD feed is not gzip: %w", err)
	}
	defer zr.Close()

	var batch []*NVDRecord
	matches := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := writeNVD(ctx, tx, batch)
		batch, matches = nil, 0
		return err
	}
	info, err := ParseNVDFeed(&capReader{r: zr, left: maxNVDJSONBytes}, func(r *NVDRecord) error {
		batch = append(batch, r)
		matches += len(r.Matches)
		if len(batch) >= nvdBatchCVEs || matches >= nvdBatchMatches {
			return flush()
		}
		return nil
	})
	if err != nil {
		return Applied{}, err
	}
	if err := flush(); err != nil {
		return Applied{}, err
	}
	if info.Records == 0 {
		return Applied{}, errors.New("intel: NVD feed held no vulnerabilities")
	}
	return Applied{Records: info.Records, Skipped: info.Skipped, Version: info.Timestamp}, nil
}

// Budgets for text stored from NVD. Vendor and product are indexed.
const (
	maxNVDDescription = 100000
	maxCPEName        = 300
	maxCPECriteria    = 1000
)

// writeNVD upserts records and replaces their CPE configurations, in a handful of
// statements. Both the bulk feeds and the single-CVE lookup write through it.
func writeNVD(ctx context.Context, tx *sql.Tx, recs []*NVDRecord) error {
	byID := make(map[string]*NVDRecord, len(recs))
	var ids []string
	for _, r := range recs {
		if _, dup := byID[r.CVE]; !dup {
			ids = append(ids, r.CVE)
		}
		byID[r.CVE] = r
	}
	if err := ensureCVEs(ctx, tx, ids); err != nil {
		return err
	}

	var ver, score, sev, vec, desc, pub, mod, status, cwes []string
	for _, id := range ids {
		r := byID[id]
		ver = append(ver, r.CVSSVersion)
		score = append(score, scoreText(r.CVSSScore))
		sev = append(sev, r.CVSSSeverity)
		vec = append(vec, r.CVSSVector)
		desc = append(desc, store.SafeText(r.Description, maxNVDDescription))
		pub = append(pub, timeText(r.Published))
		mod = append(mod, timeText(r.Modified))
		status = append(status, r.Status)
		cwes = append(cwes, store.SafeText(strings.Join(r.CWEs, ","), maxCPECriteria))
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cve_nvd
			(cve_id, cvss_version, cvss_score, cvss_severity, cvss_vector, description,
			 published_at, modified_at, vuln_status, cwes, fetched_at)
		SELECT t.id, t.ver, NULLIF(t.score, '')::real, t.sev, t.vec, t.descr,
		       NULLIF(t.pub, '')::timestamptz, NULLIF(t.modified, '')::timestamptz, t.status,
		       CASE WHEN t.cwes = '' THEN '{}'::text[] ELSE string_to_array(t.cwes, ',') END, now()
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[],
		            $7::text[], $8::text[], $9::text[], $10::text[])
		     AS t(id, ver, score, sev, vec, descr, pub, modified, status, cwes)
		ON CONFLICT (cve_id) DO UPDATE SET
			cvss_version = EXCLUDED.cvss_version, cvss_score = EXCLUDED.cvss_score,
			cvss_severity = EXCLUDED.cvss_severity, cvss_vector = EXCLUDED.cvss_vector,
			description = EXCLUDED.description, published_at = EXCLUDED.published_at,
			modified_at = EXCLUDED.modified_at, vuln_status = EXCLUDED.vuln_status,
			cwes = EXCLUDED.cwes, fetched_at = now()`,
		ids, ver, score, sev, vec, desc, pub, mod, status, cwes); err != nil {
		return fmt.Errorf("intel: store NVD records: %w", err)
	}

	if _, err := tx.ExecContext(ctx, "DELETE FROM cve_cpe WHERE cve_id = ANY($1::text[])", ids); err != nil {
		return fmt.Errorf("intel: replace CPE configurations: %w", err)
	}
	return insertMatches(ctx, tx, ids, byID)
}

func insertMatches(ctx context.Context, tx *sql.Tx, ids []string, byID map[string]*NVDRecord) error {
	var cve, cfgOp, nodeOp, crit, part, vendor, product, version []string
	var sIncl, sExcl, eIncl, eExcl, matchID []string
	var cfg, node, seq []int
	var negate, vulnerable []bool
	for _, id := range ids {
		for _, m := range byID[id].Matches {
			cve = append(cve, id)
			cfg, node, seq = append(cfg, m.ConfigSeq), append(node, m.NodeSeq), append(seq, m.MatchSeq)
			cfgOp, nodeOp = append(cfgOp, m.ConfigOperator), append(nodeOp, m.NodeOperator)
			negate, vulnerable = append(negate, m.Negate), append(vulnerable, m.Vulnerable)
			crit = append(crit, store.SafeText(m.Criteria, maxCPECriteria))
			part = append(part, store.SafeText(m.Part, maxCPEName))
			vendor = append(vendor, store.SafeText(m.Vendor, maxCPEName))
			product = append(product, store.SafeText(m.Product, maxCPEName))
			version = append(version, store.SafeText(m.Version, maxCPEName))
			sIncl = append(sIncl, store.SafeText(m.StartIncluding, maxCPEName))
			sExcl = append(sExcl, store.SafeText(m.StartExcluding, maxCPEName))
			eIncl = append(eIncl, store.SafeText(m.EndIncluding, maxCPEName))
			eExcl = append(eExcl, store.SafeText(m.EndExcluding, maxCPEName))
			matchID = append(matchID, store.SafeText(m.MatchID, maxCPEName))
		}
	}
	if len(cve) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cve_cpe
			(cve_id, config_seq, node_seq, match_seq, config_operator, node_operator, negate,
			 vulnerable, criteria, part, vendor, product, version, start_including,
			 start_excluding, end_including, end_excluding, match_id)
		SELECT * FROM unnest($1::text[], $2::int[], $3::int[], $4::int[], $5::text[], $6::text[],
		       $7::bool[], $8::bool[], $9::text[], $10::text[], $11::text[], $12::text[],
		       $13::text[], $14::text[], $15::text[], $16::text[], $17::text[], $18::text[])
		ON CONFLICT DO NOTHING`,
		cve, cfg, node, seq, cfgOp, nodeOp, negate, vulnerable, crit, part, vendor, product,
		version, sIncl, sExcl, eIncl, eExcl, matchID); err != nil {
		return fmt.Errorf("intel: store CPE configurations: %w", err)
	}
	return nil
}

func scoreText(s *float32) string {
	if s == nil {
		return ""
	}
	return strconv.FormatFloat(float64(*s), 'f', 1, 32)
}
