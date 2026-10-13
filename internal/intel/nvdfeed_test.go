package intel

import (
	"bytes"
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseCPE(t *testing.T) {
	part, vendor, product, version, err := ParseCPE(`cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`)
	if err != nil || part != "a" || vendor != "apache" || product != "http_server" || version != "2.4.49" {
		t.Errorf("got %q %q %q %q, %v", part, vendor, product, version, err)
	}

	_, vendor, product, _, err = ParseCPE(`cpe:2.3:a:we\:ird:pro\\duct:1.0:*:*:*:*:*:*:*`)
	if err != nil || vendor != "we:ird" || product != `pro\duct` {
		t.Errorf("an escaped colon or backslash was split or kept: %q %q, %v", vendor, product, err)
	}

	for _, bad := range []string{"", "cpe:/a:apache:http_server", "cpe:2.3:a:apache", "cpe:2.3:a:b:c:d:e:f:g:h:i:j:k:l"} {
		if _, _, _, _, err := ParseCPE(bad); err == nil {
			t.Errorf("ParseCPE(%q) succeeded", bad)
		}
	}
}

// nvdFeedFixture has an AND configuration (a product running on an OS), a plain
// version range, a CVE with no configuration, a CVE id that is malformed, and a
// description carrying a NUL.
const nvdFeedFixture = `{
 "resultsPerPage": 4, "startIndex": 0, "totalResults": 4, "format": "NVD_CVE", "version": "2.0",
 "timestamp": "2026-10-09T06:00:04.4689535",
 "vulnerabilities": [
  {"cve": {"id": "CVE-2021-41773", "published": "2021-10-05T09:15:07.593", "lastModified": "2026-01-01T00:00:00.000",
   "vulnStatus": "Analyzed",
   "descriptions": [{"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49"}],
   "weaknesses": [{"description": [{"value": "CWE-22"}]}],
   "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1",
      "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
   "configurations": [{"operator": "AND", "nodes": [
     {"operator": "OR", "negate": false, "cpeMatch": [
       {"vulnerable": true, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "matchCriteriaId": "A-1"}]},
     {"operator": "OR", "negate": false, "cpeMatch": [
       {"vulnerable": false, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*", "matchCriteriaId": "A-2"}]}]}]}},
  {"cve": {"id": "CVE-2020-0001", "published": "2020-01-01T00:00:00.000", "lastModified": "2020-02-01T00:00:00.000",
   "vulnStatus": "Analyzed",
   "descriptions": [{"lang": "en", "value": "bad\u0000byte"}],
   "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
       {"vulnerable": true, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50", "matchCriteriaId": "B-1"}]}]}]}},
  {"cve": {"id": "CVE-2019-0001", "published": "2019-01-01T00:00:00.000", "lastModified": "2019-02-01T00:00:00.000",
   "vulnStatus": "Rejected", "descriptions": [{"lang": "en", "value": "rejected"}]}},
  {"cve": {"id": "NOT-A-CVE", "descriptions": []}}
 ]}`

func TestParseNVDFeedStreamsAndSkipsBadIDs(t *testing.T) {
	var got []*NVDRecord
	info, err := ParseNVDFeed(strings.NewReader(nvdFeedFixture), func(r *NVDRecord) error {
		got = append(got, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.Records != 3 || info.Skipped != 1 || info.Timestamp == "" {
		t.Errorf("info = %+v, want 3 records, 1 skipped and a timestamp", info)
	}
	first := got[0]
	if first.CVSSScore == nil || *first.CVSSScore != 9.8 || first.CVSSSeverity != "CRITICAL" || len(first.CWEs) != 1 {
		t.Errorf("first record wrong: %+v", first)
	}
	if len(first.Matches) != 2 {
		t.Fatalf("matches = %d, want 2", len(first.Matches))
	}
	app, os := first.Matches[0], first.Matches[1]
	if app.ConfigOperator != "AND" || app.NodeSeq != 0 || !app.Vulnerable || app.Vendor != "apache" ||
		os.NodeSeq != 1 || os.Vulnerable {
		t.Errorf("the AND structure was lost: app=%+v os=%+v", app, os)
	}
	if r := got[1].Matches[0]; r.StartIncluding != "2.4.0" || r.EndExcluding != "2.4.50" {
		t.Errorf("version range lost: %+v", r)
	}

	if _, err := ParseNVDFeed(strings.NewReader(`[]`), func(*NVDRecord) error { return nil }); err == nil {
		t.Error("a feed that is not an object was accepted")
	}
}

func applyFeed(t *testing.T, db interface {
	InTx(ctx context.Context, fn func(*sql.Tx) error) error
}, feedJSON string) (Applied, error) {
	t.Helper()
	var applied Applied
	err := db.InTx(context.Background(), func(tx *sql.Tx) error {
		var err error
		applied, err = applyNVDFeed(context.Background(), tx, bytes.NewReader(gz(t, feedJSON)))
		return err
	})
	return applied, err
}

func TestApplyNVDFeedStoresRecordsAndConfigurations(t *testing.T) {
	db := testDB(t)
	applied, err := applyFeed(t, db, nvdFeedFixture)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Records != 3 || applied.Skipped != 1 {
		t.Errorf("applied = %+v", applied)
	}
	if n := count(t, db, "cve_nvd"); n != 3 {
		t.Errorf("cve_nvd rows = %d, want 3", n)
	}
	if n := count(t, db, "cve_cpe"); n != 3 {
		t.Errorf("cve_cpe rows = %d, want 3", n)
	}

	var desc string
	var pub time.Time
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT description, published_at FROM cve_nvd WHERE cve_id = 'CVE-2020-0001'").Scan(&desc, &pub); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(desc, 0) {
		t.Error("a NUL reached the database")
	}
	if pub.UTC().Format(time.RFC3339) != "2020-01-01T00:00:00Z" {
		t.Errorf("published = %v; NVD times are UTC and must not shift with the session zone", pub)
	}

	var d *Detail
	if err := db.InTx(context.Background(), func(tx *sql.Tx) error {
		var err error
		d, err = Show(context.Background(), tx, "CVE-2021-41773")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if d.NVD == nil || d.NVD.CVSSScore == nil || len(d.Products) != 1 || d.Products[0] != "apache:http_server" {
		t.Errorf("detail wrong: nvd=%+v products=%v (the non-vulnerable OS must not be listed)", d.NVD, d.Products)
	}
}

func TestApplyNVDFeedReplacesAChangedConfiguration(t *testing.T) {
	db := testDB(t)
	if _, err := applyFeed(t, db, nvdFeedFixture); err != nil {
		t.Fatal(err)
	}

	// NVD narrows CVE-2021-41773 to a single entry.
	narrowed := `{"timestamp":"2026-10-10T00:00:00","vulnerabilities":[{"cve":{"id":"CVE-2021-41773",
	"descriptions":[],"configurations":[{"operator":"OR","nodes":[{"operator":"OR","cpeMatch":[
	{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"}]}]}]}}]}`
	if _, err := applyFeed(t, db, narrowed); err != nil {
		t.Fatal(err)
	}

	var n int
	var version string
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT count(*), min(version) FROM cve_cpe WHERE cve_id = 'CVE-2021-41773'").Scan(&n, &version); err != nil {
		t.Fatal(err)
	}
	if n != 1 || version != "2.4.50" {
		t.Errorf("after NVD narrowed it the CVE has %d rows (version %q), want the one new row", n, version)
	}
}

func TestByProductOrdersKnownExploitedFirst(t *testing.T) {
	db := testDB(t)
	if _, err := applyFeed(t, db, nvdFeedFixture); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := db.InTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO cve_kev_cisa (cve_id, date_added) VALUES ('CVE-2020-0001', '2026-01-01')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	var hits []ProductHit
	if err := db.InTx(ctx, func(tx *sql.Tx) error {
		var err error
		hits, err = ByProduct(ctx, tx, "Apache", "HTTP_Server", 10)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("hits = %+v, want the two CVEs naming apache:http_server", hits)
	}
	if hits[0].CVE != "CVE-2020-0001" || !hits[0].KEV {
		t.Errorf("the known-exploited CVE should come first: %+v", hits)
	}
	if hits[0].Range != ">=2.4.0 <2.4.50" || hits[1].Range != "2.4.49" {
		t.Errorf("ranges = %q and %q", hits[0].Range, hits[1].Range)
	}
}

func TestNVDSourcesCoverEveryYearAndModified(t *testing.T) {
	all, err := Lookup([]string{"nvd"})
	if err != nil {
		t.Fatal(err)
	}
	want := time.Now().Year() - nvdFirstYear + 2
	if len(all) != want {
		t.Errorf("nvd group = %d sources, want %d (every year and the modified feed)", len(all), want)
	}
	one, err := Lookup([]string{"nvd-" + strconv.Itoa(nvdFirstYear)})
	if err != nil || len(one) != 1 {
		t.Errorf("a single year did not resolve: %v, %v", one, err)
	}
	for _, s := range all {
		if s.Name == "nvd-modified" != s.anySize {
			t.Errorf("%s: only the modified feed may skip the shrink guard", s.Name)
		}
	}
}

func TestOnlyTheModifiedFeedMayShrink(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	small := `{"timestamp":"2026-10-10T00:00:00","vulnerabilities":[{"cve":{"id":"CVE-2020-0001","descriptions":[]}}]}`

	bigSrv, _ := feed(t, gz(t, nvdFeedFixture), `"big"`)
	smallSrv, _ := feed(t, gz(t, small), `"small"`)
	src := func(name, url string, anySize bool) Source {
		return Source{Name: name, URL: url, Group: "nvd", Optional: true, anySize: anySize, apply: applyNVDFeed}
	}

	for _, name := range []string{"nvd-modified", "nvd-2020"} {
		if _, err := Sync(ctx, db, src(name, bigSrv.URL, name == "nvd-modified"), Options{Client: bigSrv.Client()}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Sync(ctx, db, src("nvd-modified", smallSrv.URL, true), Options{Client: smallSrv.Client()}); err != nil {
		t.Errorf("a quiet week's modified feed was refused as a shrink: %v", err)
	}
	if _, err := Sync(ctx, db, src("nvd-2020", smallSrv.URL, false), Options{Client: smallSrv.Client()}); err == nil ||
		!strings.Contains(err.Error(), "shrank") {
		t.Errorf("a yearly feed that lost most of its records was accepted: %v", err)
	}
}
