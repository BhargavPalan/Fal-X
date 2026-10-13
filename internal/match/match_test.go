package match

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/store"
	"github.com/BhargavPalan/Fal-X/internal/storetest"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.4.49", "2.4.49", 0},
		{"2.4.10", "2.4.9", 1},
		{"2.4.7", "2.4.50", -1},
		{"1.0", "1.0.0", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.0beta", "1.0", -1},
		{"1.0rc1", "1.0rc2", -1},
		{"6.6.1p1", "6.6.1", 1},
		{"6.6.1p1", "6.6.2", -1},
		{"1.1.1k", "1.1.1l", -1},
		{"10", "9", 1},
		{"0.9.8", "1.0.0", -1},
	}
	for _, c := range cases {
		got := Compare(c.a, c.b)
		if (got < 0) != (c.want < 0) || (got > 0) != (c.want > 0) {
			t.Errorf("Compare(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
		if back := Compare(c.b, c.a); (back < 0) != (c.want > 0) || (back > 0) != (c.want < 0) {
			t.Errorf("Compare is not antisymmetric for %q and %q", c.a, c.b)
		}
	}
}

func TestRangeContains(t *testing.T) {
	r := Range{StartIncluding: "2.4.0", EndExcluding: "2.4.50"}
	for v, want := range map[string]bool{"2.4.0": true, "2.4.49": true, "2.4.50": false, "2.3.9": false, "2.4.7": true} {
		if got := r.Contains(v); got != want {
			t.Errorf("%v contains %q = %v, want %v", r, v, got, want)
		}
	}
	if !(Range{}).Contains("1.2.3") || (Range{}).Bounded() {
		t.Error("an unbounded range should contain everything")
	}
	if (Range{StartExcluding: "1.0"}).Contains("1.0") || !(Range{EndIncluding: "1.0"}).Contains("1.0") {
		t.Error("inclusive and exclusive bounds are swapped")
	}
	if got := r.String(); got != ">=2.4.0 <2.4.50" {
		t.Errorf("String = %q", got)
	}
}

func TestObservations(t *testing.T) {
	cases := []struct {
		key, value string
		name, ver  string
		distro     string
	}{
		{"tech", "Apache HTTP Server:2.4.7", "Apache HTTP Server", "2.4.7", ""},
		{"tech", "jQuery:3.6.0", "jQuery", "3.6.0", ""},
		{"tech", "Cloudflare", "Cloudflare", "", ""},
		{"tech", "HTTP/3", "HTTP/3", "", ""},
		{"tech", "Foo:Browser", "Foo", "", ""},
		{"server", "Apache/2.4.7 (Ubuntu)", "Apache", "2.4.7", "Ubuntu"},
		{"server", "nginx/1.18.0", "nginx", "1.18.0", ""},
		{"server", "cloudflare", "cloudflare", "", ""},
	}
	for _, c := range cases {
		got := Observations(c.key, c.value)
		if len(got) == 0 {
			t.Errorf("%s %q: nothing read", c.key, c.value)
			continue
		}
		if got[0].Name != c.name || got[0].Version != c.ver || got[0].Distro != c.distro {
			t.Errorf("%s %q = %+v, want %s %s %s", c.key, c.value, got[0], c.name, c.ver, c.distro)
		}
	}
	if got := Observations("server", "Apache/2.4.7 PHP/5.5.9-1ubuntu4.14 (Ubuntu) OpenSSL/1.0.1f"); len(got) != 3 {
		t.Errorf("a header with three products gave %d sightings", len(got))
	}
	if got := Observations("title", "Apache/2.4.7"); got != nil {
		t.Errorf("an attribute that does not name software was read: %v", got)
	}
}

func TestResolveKnownNames(t *testing.T) {
	for name, want := range map[string]Product{
		"Apache HTTP Server": {"apache", "http_server"},
		"Microsoft-IIS":      {"microsoft", "internet_information_services"},
		"nginx":              {"nginx", "nginx"},
		"OpenSSH":            {"openbsd", "openssh"},
	} {
		if got, ok := Resolve(name); !ok || got != want {
			t.Errorf("Resolve(%q) = %v, %v", name, got, ok)
		}
	}
	if _, ok := Resolve("Cloudflare"); ok {
		t.Error("an unlisted name resolved")
	}
}

func testDB(t *testing.T) *store.DB {
	db := storetest.NewTestDB(t)
	ctx := context.Background()
	for _, tbl := range []string{"cve_nvd", "cve_kev_cisa", "cve"} {
		if _, err := db.SQL().ExecContext(ctx, "DELETE FROM "+tbl); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

type cpeFixture struct {
	cve, cfgOp, vendor, product, version string
	vulnerable                           bool
	cfg, nodeSeq                         int
	startIncl, endExcl                   string
}

func seedCVEs(t *testing.T, db *store.DB, rows []cpeFixture, kev ...string) {
	t.Helper()
	ctx := context.Background()
	for _, r := range rows {
		if _, err := db.SQL().ExecContext(ctx, "INSERT INTO cve (cve_id) VALUES ($1) ON CONFLICT DO NOTHING", r.cve); err != nil {
			t.Fatal(err)
		}
		if _, err := db.SQL().ExecContext(ctx, `
			INSERT INTO cve_cpe (cve_id, config_seq, node_seq, match_seq, config_operator, node_operator,
			                     vulnerable, criteria, vendor, product, version, start_including, end_excluding)
			VALUES ($1, $2, $3, $4, $5, 'OR', $6, 'cpe:2.3:a:x', $7, $8, $9, $10, $11)`,
			r.cve, r.cfg, r.nodeSeq, r.nodeSeq*10+r.cfg, r.cfgOp, r.vulnerable, r.vendor, r.product,
			r.version, r.startIncl, r.endExcl); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range kev {
		if _, err := db.SQL().ExecContext(ctx, "INSERT INTO cve (cve_id) VALUES ($1) ON CONFLICT DO NOTHING", id); err != nil {
			t.Fatal(err)
		}
		if _, err := db.SQL().ExecContext(ctx,
			"INSERT INTO cve_kev_cisa (cve_id, date_added) VALUES ($1, '2026-01-01')", id); err != nil {
			t.Fatal(err)
		}
	}
}

type world struct {
	db    *store.DB
	slug  string
	orgID int64
}

func newWorld(t *testing.T) *world {
	t.Helper()
	return newWorldOn(t, testDB(t))
}

func newWorldOn(t *testing.T, db *store.DB) *world {
	t.Helper()
	slug := fmt.Sprintf("match-%d", time.Now().UnixNano())
	id, err := db.EnsureOrg(context.Background(), slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.SQL().ExecContext(context.Background(), "DELETE FROM org WHERE slug = $1", slug)
	})
	return &world{db: db, slug: slug, orgID: id}
}

func (w *world) tx(t *testing.T, fn func(*sql.Tx) error) {
	t.Helper()
	scoped, err := w.db.WithOrg(context.Background(), w.orgID)
	if err != nil {
		t.Fatal(err)
	}
	if err := scoped.InTx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func (w *world) asset(t *testing.T, ident string, attrs map[string]string) {
	t.Helper()
	w.tx(t, func(tx *sql.Tx) error {
		ref, err := graph.Resolve(context.Background(), tx, w.orgID, graph.TypeURL, ident, ident, 0)
		if err != nil {
			return err
		}
		for k, v := range attrs {
			if err := graph.AddFact(context.Background(), tx, ref, k, v, "test", true, 1, 0); err != nil {
				return err
			}
		}
		return nil
	})
}

func (w *world) run(t *testing.T) (Summary, map[string]Listed) {
	t.Helper()
	var sum Summary
	var listed []Listed
	w.tx(t, func(tx *sql.Tx) error {
		var err error
		if sum, err = Run(context.Background(), tx, w.orgID); err != nil {
			return err
		}
		listed, err = List(context.Background(), tx, "", 1000)
		return err
	})
	byKey := map[string]Listed{}
	for _, l := range listed {
		byKey[l.Asset+"|"+l.CVE] = l
	}
	return sum, byKey
}

func TestRunClassifiesEveryKindOfMatch(t *testing.T) {
	w := newWorld(t)
	seedCVEs(t, w.db, []cpeFixture{
		{cve: "CVE-2021-41773", vendor: "apache", product: "http_server", version: "2.4.49", vulnerable: true},
		{cve: "CVE-2020-0001", vendor: "apache", product: "http_server", version: "*", vulnerable: true, startIncl: "2.4.0", endExcl: "2.4.50"},
		{cve: "CVE-2019-0001", vendor: "apache", product: "http_server", version: "*", vulnerable: true, cfgOp: "AND", endExcl: "2.5"},
		{cve: "CVE-2019-0001", vendor: "linux", product: "linux_kernel", version: "-", vulnerable: false, cfgOp: "AND", nodeSeq: 1},
		{cve: "CVE-2018-0001", vendor: "apache", product: "http_server", version: "*", vulnerable: true, endExcl: "2.2.0"},
		{cve: "CVE-2012-0001", vendor: "apache", product: "http_server", version: "*", vulnerable: true},
		{cve: "CVE-2017-0001", vendor: "widgetsoft", product: "widget", version: "*", vulnerable: true, endExcl: "2.0"},
	}, "CVE-2021-41773", "CVE-2012-0001")

	w.asset(t, "https://a.example.com", map[string]string{
		"tech": "Apache HTTP Server:2.4.49", "server": "Apache/2.4.49 (Ubuntu)",
	})
	w.asset(t, "https://b.example.com", map[string]string{"tech": "Widget:1.5"})
	w.asset(t, "https://c.example.com", map[string]string{"tech": "Apache HTTP Server"})
	w.asset(t, "https://d.example.com", map[string]string{"tech": "Cloudflare", "server": "cloudflare"})

	sum, got := w.run(t)

	check := func(key, tier, conf string) Listed {
		t.Helper()
		l, ok := got[key]
		if !ok {
			t.Errorf("%s: no match", key)
			return l
		}
		if l.Tier != tier || l.Confidence != conf {
			t.Errorf("%s: tier %s/%s, want %s/%s (%s)", key, l.Tier, l.Confidence, tier, conf, l.Reason)
		}
		return l
	}

	// The banner names Ubuntu, which backports fixes, so even an exact match is only medium.
	if l := check("https://a.example.com|CVE-2021-41773", TierAffected, "medium"); !l.KEV || l.Caveat == "" {
		t.Errorf("the known-exploited exact match lost its KEV flag or caveat: %+v", l)
	}
	check("https://a.example.com|CVE-2020-0001", TierAffected, "medium")
	if l := check("https://a.example.com|CVE-2019-0001", TierConditional, "medium"); l.Conditions == "" {
		t.Errorf("a conditional match should say what it is conditional on: %+v", l)
	}
	if l := check("https://a.example.com|CVE-2012-0001", TierAffected, "medium"); !strings.Contains(l.Reason, "every version") {
		t.Errorf("reason = %q", l.Reason)
	}
	if _, ok := got["https://a.example.com|CVE-2018-0001"]; ok {
		t.Error("a CVE whose range excludes the version was matched")
	}

	check("https://b.example.com|CVE-2017-0001", TierUnverified, "low")

	check("https://c.example.com|CVE-2021-41773", TierPossible, "low")
	check("https://c.example.com|CVE-2012-0001", TierPossible, "low")
	if _, ok := got["https://c.example.com|CVE-2020-0001"]; ok {
		t.Error("with no version known, a CVE that is not known-exploited was reported")
	}

	for k := range got {
		if strings.HasPrefix(k, "https://d.example.com") {
			t.Errorf("software with no CVE data matched: %s", k)
		}
	}

	if sum.Assets != 3 || sum.Matches[TierPossible] != 2 || sum.Matches[TierUnverified] != 1 {
		t.Errorf("summary = %+v", sum)
	}

	var n int
	w.tx(t, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), `
			SELECT count(*) FROM entity_fact WHERE key = 'software' AND value = 'apache:http_server 2.4.49'`).Scan(&n)
	})
	if n != 1 {
		t.Errorf("the detected software was recorded %d times, want once", n)
	}
}

func TestRunReplacesTheSetAndStaysInItsTenant(t *testing.T) {
	w := newWorld(t)
	seedCVEs(t, w.db, []cpeFixture{
		{cve: "CVE-2020-0001", vendor: "apache", product: "http_server", version: "*", vulnerable: true, endExcl: "2.4.50"},
	})
	w.asset(t, "https://a.example.com", map[string]string{"tech": "Apache HTTP Server:2.4.49"})

	if sum, _ := w.run(t); sum.Total() != 1 {
		t.Fatalf("first run matched %d, want 1", sum.Total())
	}

	// The software is upgraded and seen again.
	w.asset(t, "https://a.example.com", map[string]string{"tech": "Apache HTTP Server:2.4.60"})
	w.tx(t, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), "DELETE FROM entity_fact WHERE key = 'tech' AND value LIKE '%2.4.49'")
		return err
	})
	if sum, _ := w.run(t); sum.Total() != 0 {
		t.Errorf("after the upgrade %d matches remain; a CVE must stop being reported", sum.Total())
	}

	other := newWorldOn(t, w.db)
	other.asset(t, "https://z.example.com", map[string]string{"tech": "Apache HTTP Server:2.4.1"})
	other.run(t)
	_, mine := w.run(t)
	for k := range mine {
		if strings.Contains(k, "z.example.com") {
			t.Errorf("another organization's match is visible: %s", k)
		}
	}
}

func TestObservationsFromNmap(t *testing.T) {
	cases := []struct {
		value, name, version, distro string
	}{
		{"ssh OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)", "OpenSSH", "6.6.1p1", "Ubuntu"},
		{"http Apache httpd 2.4.7 ((Ubuntu))", "Apache httpd", "2.4.7", "Ubuntu"},
		{"ftp ProFTPD 1.3.5", "ProFTPD", "1.3.5", ""},
		{"smtp Postfix smtpd", "Postfix smtpd", "", ""},
	}
	for _, c := range cases {
		got := Observations("service", c.value)
		if len(got) != 1 || got[0].Name != c.name || got[0].Version != c.version || got[0].Distro != c.distro {
			t.Errorf("%q = %+v, want %s %s %s", c.value, got, c.name, c.version, c.distro)
		}
	}
	if got := Observations("service", "ssh"); got != nil {
		t.Errorf("a port nmap could not identify produced %v", got)
	}
	for name, want := range map[string]Product{
		"Apache httpd":  {"apache", "http_server"},
		"OpenSSH":       {"openbsd", "openssh"},
		"Postfix smtpd": {"postfix", "postfix"},
	} {
		if got, ok := Resolve(name); !ok || got != want {
			t.Errorf("Resolve(%q) = %v, %v", name, got, ok)
		}
	}
}
