package intel

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/store"
)

const kevFixture = `{
 "catalogVersion": "2026.10.08",
 "vulnerabilities": [
  {"cveID":"CVE-2015-5477","vendorProject":"ISC","product":"BIND","vulnerabilityName":" ISC BIND Data Processing Errors ",
   "dateAdded":"2026-10-08","shortDescription":"desc","requiredAction":"patch","dueDate":"2026-10-11",
   "knownRansomwareCampaignUse":"Known","notes":"n","cwes":["CWE-19"]},
  {"cveID":"cve-2021-44228","vendorProject":"Apache","product":"Log4j2","vulnerabilityName":"Log4Shell",
   "dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Unknown","cwes":null},
  {"cveID":"NOT-A-CVE","vendorProject":"x","product":"y","dateAdded":"2026-01-01"},
  {"cveID":"CVE-2020-0001","vendorProject":"x","product":"y","dateAdded":"not a date"}
 ]}`

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

const epssFixture = "#model_version:v2026.06.15,score_date:2026-10-08T12:00:21Z\n" +
	"cve,epss,percentile\n" +
	"CVE-2015-5477,0.5,0.9\n" +
	"CVE-2021-44228,0.97,0.999\n" +
	"CVE-2020-0001,1.5,0.2\n" + // score out of range
	"garbage,0.1,0.1\n" + // not a CVE id
	"CVE-2020-0002,0.1\n" // wrong field count

func TestParseKEV(t *testing.T) {
	c, err := ParseKEV(strings.NewReader(kevFixture))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "2026.10.08" {
		t.Errorf("version = %q", c.Version)
	}
	if len(c.Entries) != 2 || c.Skipped != 2 {
		t.Fatalf("entries=%d skipped=%d, want 2 and 2 (bad id and bad date skipped)", len(c.Entries), c.Skipped)
	}
	e := c.Entries[0]
	if e.CVE != "CVE-2015-5477" || e.Name != "ISC BIND Data Processing Errors" || !e.KnownRansomware ||
		e.DueDate == nil || len(e.CWEs) != 1 {
		t.Errorf("first entry wrong: %+v", e)
	}
	if got := c.Entries[1]; got.CVE != "CVE-2021-44228" || got.KnownRansomware || got.DueDate != nil {
		t.Errorf("lower-case id not normalised, or defaults wrong: %+v", got)
	}
}

func TestParseKEVRejectsEmpty(t *testing.T) {
	for _, in := range []string{`{}`, `{"vulnerabilities":[]}`, `not json`, `{"vulnerabilities":[{"cveID":"x","dateAdded":"1"}]}`} {
		if _, err := ParseKEV(strings.NewReader(in)); err == nil {
			t.Errorf("ParseKEV(%q) succeeded; an empty or unusable feed must not look like a clean sync", in)
		}
	}
}

func TestParseEPSS(t *testing.T) {
	f, err := ParseEPSS(bytes.NewReader(gz(t, epssFixture)))
	if err != nil {
		t.Fatal(err)
	}
	if f.ModelVersion != "v2026.06.15" || f.ScoreDate.Format("2006-01-02") != "2026-10-08" {
		t.Errorf("metadata wrong: %q %v", f.ModelVersion, f.ScoreDate)
	}
	if len(f.Scores) != 2 || f.Skipped != 3 {
		t.Fatalf("scores=%d skipped=%d, want 2 and 3", len(f.Scores), f.Skipped)
	}
	if f.Scores[1].CVE != "CVE-2021-44228" || f.Scores[1].Score != 0.97 {
		t.Errorf("score wrong: %+v", f.Scores[1])
	}
}

func TestParseEPSSRejectsBadInput(t *testing.T) {
	if _, err := ParseEPSS(strings.NewReader("plain text, not gzip")); err == nil {
		t.Error("non-gzip body accepted")
	}
	if _, err := ParseEPSS(bytes.NewReader(gz(t, "#m:1\nwrong,header\nCVE-2020-0001,0.1,0.1\n"))); err == nil {
		t.Error("wrong header accepted")
	}
	if _, err := ParseEPSS(bytes.NewReader(gz(t, "cve,epss,percentile\n"))); err == nil {
		t.Error("a feed with no scores must not look like a clean sync")
	}
}

func TestCVEsIn(t *testing.T) {
	got := CVEsIn(`medium CVE-2023-48795 ["Vulnerable to Terrapin"] cve-2023-48795 and CVE-2021-44228, CVE-12-1`)
	if len(got) != 2 || got[0] != "CVE-2023-48795" || got[1] != "CVE-2021-44228" {
		t.Errorf("CVEsIn = %v, want the two distinct valid ids in first-seen order", got)
	}
	if len(CVEsIn("no ids here")) != 0 {
		t.Error("found an id in text with none")
	}
}

func TestLookup(t *testing.T) {
	if got, err := Lookup(nil); err != nil || len(got) != len(Sources) {
		t.Errorf("Lookup(nil) = %d, %v", len(got), err)
	}
	if got, err := Lookup([]string{" KEV "}); err != nil || len(got) != 1 || got[0].Name != "kev" {
		t.Errorf("Lookup(KEV) = %v, %v", got, err)
	}
	if _, err := Lookup([]string{"nvd"}); err == nil {
		t.Error("an unbuilt source was accepted")
	}
}

// ---- database tests ----

// testDB opens the integration database, serialised with the other packages'
// tests through the shared advisory lock, or skips. The key must match
// store.testLockKey.
func testDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("FALX_TEST_DSN"))
	if dsn == "" {
		t.Skip("set FALX_TEST_DSN to run database integration tests")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, store.DefaultOptions(dsn))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	lock, err := db.SQL().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.ExecContext(ctx, "SELECT pg_advisory_lock($1)", 7263001); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = lock.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", 7263001)
		_ = lock.Close()
	})
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Start from nothing so counts are exact. These tables are global, so this is
	// only safe because the lock above excludes every other test.
	for _, tbl := range []string{"source_watermark", "cve_nvd", "cve_epss", "cve_kev_cisa", "cve"} {
		if _, err := db.SQL().ExecContext(ctx, "DELETE FROM "+tbl); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// feed serves a fixture over HTTPS with an ETag, and counts full downloads.
func feed(t *testing.T, body []byte, etag string) (*httptest.Server, *int32) {
	t.Helper()
	var downloads int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		atomic.AddInt32(&downloads, 1)
		w.Header().Set("ETag", etag)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &downloads
}

func count(t *testing.T, db *store.DB, table string) (n int) {
	t.Helper()
	if err := db.SQL().QueryRowContext(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSyncKEVStoresAndSkipsWhenUnchanged(t *testing.T) {
	db := testDB(t)
	srv, downloads := feed(t, []byte(kevFixture), `"v1"`)
	src := Source{Name: "kev", URL: srv.URL, apply: applyKEV}
	opts := Options{Client: srv.Client()}
	ctx := context.Background()

	res, err := Sync(ctx, db, src, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.NotModified || res.Records != 2 || res.Skipped != 2 || res.Version != "2026.10.08" {
		t.Errorf("first sync: %+v", res)
	}
	if count(t, db, "cve") != 2 || count(t, db, "cve_kev_cisa") != 2 {
		t.Errorf("rows: cve=%d kev=%d, want 2 and 2", count(t, db, "cve"), count(t, db, "cve_kev_cisa"))
	}

	// Same ETag: the server answers 304 and nothing is downloaded or rewritten.
	res, err = Sync(ctx, db, src, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NotModified || atomic.LoadInt32(downloads) != 1 {
		t.Errorf("second sync should be a 304 (downloads=%d): %+v", atomic.LoadInt32(downloads), res)
	}

	// Force ignores the validators and rewrites idempotently.
	opts.Force = true
	if _, err := Sync(ctx, db, src, opts); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(downloads) != 2 || count(t, db, "cve_kev_cisa") != 2 {
		t.Errorf("forced sync: downloads=%d kev rows=%d", atomic.LoadInt32(downloads), count(t, db, "cve_kev_cisa"))
	}
}

func TestSyncEPSSAndShow(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	kev, _ := feed(t, []byte(kevFixture), `"k"`)
	eps, _ := feed(t, gz(t, epssFixture), `"e"`)
	if _, err := Sync(ctx, db, Source{Name: "kev", URL: kev.URL, apply: applyKEV}, Options{Client: kev.Client()}); err != nil {
		t.Fatal(err)
	}
	res, err := Sync(ctx, db, Source{Name: "epss", URL: eps.URL, apply: applyEPSS}, Options{Client: eps.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 2 || res.Version != "v2026.06.15" {
		t.Errorf("epss: %+v", res)
	}

	var d *Detail
	if err := db.InTx(ctx, func(tx *sql.Tx) error {
		var err error
		d, err = Show(ctx, tx, "cve-2015-5477")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !d.Known || d.KEV == nil || d.EPSS == nil {
		t.Fatalf("detail incomplete: %+v", d)
	}
	if d.KEV.Product != "BIND" || !d.KEV.KnownRansomware || d.EPSS.Score != 0.5 {
		t.Errorf("detail wrong: %+v %+v", d.KEV, d.EPSS)
	}

	// Unknown to every source is a different answer from known and not exploited.
	_ = db.InTx(ctx, func(tx *sql.Tx) error {
		d, _ = Show(ctx, tx, "CVE-1999-9999")
		return nil
	})
	if d.Known || d.KEV != nil {
		t.Errorf("an unseen CVE reported as known: %+v", d)
	}
}

func TestSyncFailureLeavesPreviousDataAndWatermark(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	good, _ := feed(t, []byte(kevFixture), `"v1"`)
	if _, err := Sync(ctx, db, Source{Name: "kev", URL: good.URL, apply: applyKEV}, Options{Client: good.Client()}); err != nil {
		t.Fatal(err)
	}

	// A new version that is garbage: the sync must fail and change nothing.
	bad, _ := feed(t, []byte(`{"vulnerabilities":[]}`), `"v2"`)
	_, err := Sync(ctx, db, Source{Name: "kev", URL: bad.URL, apply: applyKEV}, Options{Client: bad.Client(), Force: true})
	if err == nil {
		t.Fatal("an empty feed was accepted")
	}
	if count(t, db, "cve_kev_cisa") != 2 {
		t.Errorf("a failed sync damaged the stored data: %d rows", count(t, db, "cve_kev_cisa"))
	}
	var etag string
	_ = db.SQL().QueryRowContext(context.Background(), "SELECT etag FROM source_watermark WHERE source='kev'").Scan(&etag)
	if etag != `"v1"` {
		t.Errorf("a failed sync moved the watermark to %q", etag)
	}
}

func TestSyncRefusesPlainHTTPAndHTTPErrors(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if _, err := Sync(ctx, db, Source{Name: "kev", URL: "http://example.invalid/x", apply: applyKEV}, Options{}); err == nil {
		t.Error("a non-https source was accepted")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := Sync(ctx, db, Source{Name: "kev", URL: srv.URL, apply: applyKEV}, Options{Client: srv.Client()}); err == nil {
		t.Error("an HTTP 500 was treated as success")
	}
}

func TestSearchTreatsTextLiterally(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	kev, _ := feed(t, []byte(kevFixture), `"k"`)
	if _, err := Sync(ctx, db, Source{Name: "kev", URL: kev.URL, apply: applyKEV}, Options{Client: kev.Client()}); err != nil {
		t.Fatal(err)
	}
	search := func(q string) (hits []SearchHit) {
		_ = db.InTx(ctx, func(tx *sql.Tx) error {
			var err error
			hits, err = Search(ctx, tx, q, 10)
			return err
		})
		return hits
	}
	if got := search("log4j"); len(got) != 1 || got[0].CVE != "CVE-2021-44228" {
		t.Errorf("search log4j = %+v", got)
	}
	// A bare wildcard is a literal character here, not "match everything".
	for _, q := range []string{"%", "_", `\`} {
		if got := search(q); len(got) != 0 {
			t.Errorf("search %q matched %d rows; LIKE metacharacters must be literal", q, len(got))
		}
	}
}
