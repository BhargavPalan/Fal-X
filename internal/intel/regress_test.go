package intel

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// Regression tests: each one fails without the fix it pins.

func kevWith(ids ...string) string {
	var rows []string
	for _, id := range ids {
		rows = append(rows, `{"cveID":"`+id+`","vendorProject":"v","product":"p","vulnerabilityName":"n","dateAdded":"2026-01-01","knownRansomwareCampaignUse":"Unknown"}`)
	}
	return `{"catalogVersion":"x","vulnerabilities":[` + strings.Join(rows, ",") + `]}`
}

func isKEV(t *testing.T, db interface {
	InTx(ctx context.Context, fn func(*sql.Tx) error) error
}, id string) bool {
	t.Helper()
	var d *Detail
	if err := db.InTx(context.Background(), func(tx *sql.Tx) error {
		var err error
		d, err = Show(context.Background(), tx, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return d.KEV != nil
}

// TestWithdrawnKEVEntriesAreRemoved pins the worst failure this product can have:
// CISA withdraws an entry, the sync only upserts, the row stays forever, and the
// prioritizer keeps telling an operator to "Act" on a CVE that is no longer on the
// list.
func TestWithdrawnKEVEntriesAreRemoved(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	both, _ := feed(t, []byte(kevWith("CVE-2021-44228", "CVE-2015-5477")), `"v1"`)
	if _, err := Sync(ctx, db, Source{Name: "kev", URL: both.URL, apply: applyKEV}, Options{Client: both.Client()}); err != nil {
		t.Fatal(err)
	}
	if !isKEV(t, db, "CVE-2021-44228") {
		t.Fatal("setup: the entry was not stored")
	}

	// Upstream withdraws CVE-2021-44228.
	one, _ := feed(t, []byte(kevWith("CVE-2015-5477")), `"v2"`)
	if _, err := Sync(ctx, db, Source{Name: "kev", URL: one.URL, apply: applyKEV}, Options{Client: one.Client(), Force: true}); err != nil {
		t.Fatal(err)
	}
	if isKEV(t, db, "CVE-2021-44228") {
		t.Error("a withdrawn KEV entry is still reported as known exploited")
	}
	if !isKEV(t, db, "CVE-2015-5477") {
		t.Error("an entry still on the list was removed")
	}
	if count(t, db, "cve_kev_cisa") != 1 {
		t.Errorf("kev rows = %d, want 1", count(t, db, "cve_kev_cisa"))
	}
}

// TestStaleEPSSScoresAreRemoved pins the same for EPSS: a CVE the new scoring run
// no longer lists must not keep an old probability that reads as current.
func TestStaleEPSSScoresAreRemoved(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	day1 := "#model_version:v1,score_date:2026-10-08T12:00:00Z\ncve,epss,percentile\nCVE-2015-5477,0.5,0.9\nCVE-2021-44228,0.97,0.99\n"
	day2 := "#model_version:v1,score_date:2026-10-09T12:00:00Z\ncve,epss,percentile\nCVE-2015-5477,0.6,0.9\n"

	a, _ := feed(t, gz(t, day1), `"e1"`)
	if _, err := Sync(ctx, db, Source{Name: "epss", URL: a.URL, apply: applyEPSS}, Options{Client: a.Client()}); err != nil {
		t.Fatal(err)
	}
	b, _ := feed(t, gz(t, day2), `"e2"`)
	if _, err := Sync(ctx, db, Source{Name: "epss", URL: b.URL, apply: applyEPSS}, Options{Client: b.Client(), Force: true}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, "cve_epss"); n != 1 {
		t.Errorf("cve_epss rows = %d, want 1: a score from the old run survived", n)
	}
}

// TestOversizedFeedIsAnErrorNotATruncatedSuccess pins that hitting the size cap is
// reported. A LimitReader ends in a clean EOF, so a feed bigger than the cap used
// to parse as a short feed, write a watermark, and then answer 304 forever.
func TestOversizedFeedIsAnErrorNotATruncatedSuccess(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	old := maxEPSSBytes
	maxEPSSBytes = 200
	t.Cleanup(func() { maxEPSSBytes = old })

	var sb strings.Builder
	sb.WriteString("#model_version:v1,score_date:2026-10-08T12:00:00Z\ncve,epss,percentile\n")
	for i := 1000; i < 1100; i++ {
		sb.WriteString("CVE-2020-" + itoa(i) + ",0.1,0.1\n")
	}
	srv, _ := feed(t, gz(t, sb.String()), `"big"`)
	_, err := Sync(ctx, db, Source{Name: "epss", URL: srv.URL, apply: applyEPSS}, Options{Client: srv.Client()})
	if err == nil {
		t.Fatal("a feed larger than the cap was accepted as a complete feed")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("the error should say the feed was too large: %v", err)
	}
	var etag string
	_ = db.SQL().QueryRowContext(ctx, "SELECT etag FROM source_watermark WHERE source='epss'").Scan(&etag)
	if etag != "" {
		t.Errorf("a failed sync wrote a watermark (%q), so the next sync would get a 304 and never heal", etag)
	}
	if count(t, db, "cve_epss") != 0 {
		t.Errorf("a truncated feed left %d rows behind", count(t, db, "cve_epss"))
	}
}

func TestWireCapIsAnErrorToo(t *testing.T) {
	db := testDB(t)
	old := maxFeedBytes
	maxFeedBytes = 50
	t.Cleanup(func() { maxFeedBytes = old })

	srv, _ := feed(t, []byte(kevWith("CVE-2015-5477", "CVE-2021-44228")), `"k"`)
	if _, err := Sync(context.Background(), db, Source{Name: "kev", URL: srv.URL, apply: applyKEV}, Options{Client: srv.Client()}); err == nil {
		t.Fatal("a body larger than the wire cap was accepted")
	}
}

// TestSuddenShrinkIsRefusedUnlessForced pins the second line of defence: a feed
// that suddenly holds far fewer records than the last good sync is more likely a
// partial or wrong response than the real state of the world.
func TestSuddenShrinkIsRefusedUnlessForced(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	full, _ := feed(t, []byte(kevWith("CVE-2015-5477", "CVE-2021-44228", "CVE-2020-0001", "CVE-2020-0002")), `"f"`)
	if _, err := Sync(ctx, db, Source{Name: "kev", URL: full.URL, apply: applyKEV}, Options{Client: full.Client()}); err != nil {
		t.Fatal(err)
	}
	tiny, _ := feed(t, []byte(kevWith("CVE-2015-5477")), `"t"`)
	src := Source{Name: "kev", URL: tiny.URL, apply: applyKEV}

	_, err := Sync(ctx, db, src, Options{Client: tiny.Client(), Force: false})
	if err == nil || !strings.Contains(err.Error(), "shrank") {
		t.Fatalf("a feed that lost 3 of 4 records was accepted: %v", err)
	}
	if count(t, db, "cve_kev_cisa") != 4 {
		t.Errorf("a refused sync changed the data: %d rows", count(t, db, "cve_kev_cisa"))
	}
	if _, err := Sync(ctx, db, src, Options{Client: tiny.Client(), AllowShrink: true}); err != nil {
		t.Errorf("an explicit AllowShrink should apply the smaller feed: %v", err)
	}
	if count(t, db, "cve_kev_cisa") != 1 {
		t.Errorf("rows after an allowed shrink = %d, want 1", count(t, db, "cve_kev_cisa"))
	}
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%10]}, b...)
		n /= 10
	}
	return string(b)
}
