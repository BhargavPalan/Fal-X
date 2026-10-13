package intel

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"sort"
	"strings"
	"testing"
)

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := files[name]
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func advisory(id, aliases, pkg string) string {
	return `{"id":"` + id + `","modified":"2026-10-01T00:00:00Z","published":"2026-09-01T00:00:00Z",
	"aliases":[` + aliases + `],"summary":"summary of ` + id + `","details":"details",
	"affected":[{"package":{"ecosystem":"Go","name":"` + pkg + `","purl":"pkg:golang/` + pkg + `"},
	"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}],"versions":["1.0.0"]}]}`
}

func syncOSV(t *testing.T, db interface {
	InTx(ctx context.Context, fn func(*sql.Tx) error) error
}, eco string, archive []byte) (Applied, error) {
	t.Helper()
	var applied Applied
	err := db.InTx(context.Background(), func(tx *sql.Tx) error {
		var err error
		applied, err = applyOSV(eco)(context.Background(), tx, bytes.NewReader(archive))
		return err
	})
	return applied, err
}

func TestParseOSV(t *testing.T) {
	adv, err := ParseOSV(strings.NewReader(advisory("GHSA-aaaa-bbbb-cccc", `"CVE-2021-44228"`, "example.com/mod")))
	if err != nil {
		t.Fatal(err)
	}
	if adv.ID != "GHSA-aaaa-bbbb-cccc" || len(adv.Aliases) != 1 || len(adv.Affected) != 1 {
		t.Fatalf("parsed wrong: %+v", adv)
	}
	if got := adv.Affected[0]; got.Name != "example.com/mod" || len(got.Versions) != 1 || !strings.Contains(string(got.Ranges), "SEMVER") {
		t.Errorf("affected package wrong: %+v", got)
	}

	hostile := `{"id":"X-1","modified":"2026-10-01T00:00:00Z","details":"a\u0000b",
	"affected":[{"package":{"name":"p\u0000q"},"ranges":[{"type":"\u0000"}]}]}`
	adv, err = ParseOSV(strings.NewReader(hostile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(adv.Details, 0) || strings.ContainsRune(adv.Affected[0].Name, 0) ||
		strings.Contains(string(adv.Affected[0].Ranges), `\u0000`) {
		t.Errorf("a NUL survived parsing, and Postgres refuses it: %+v", adv)
	}

	for _, bad := range []string{`{}`, `{"id":"X"}`, `{"id":"X","modified":"yesterday"}`, `not json`} {
		if _, err := ParseOSV(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseOSV(%q) succeeded", bad)
		}
	}
}

func TestSyncOSVStoresAdvisoriesAndResolvesAliases(t *testing.T) {
	db := testDB(t)
	archive := zipOf(t, map[string]string{
		"GHSA-aaaa-bbbb-cccc.json": advisory("GHSA-aaaa-bbbb-cccc", `"CVE-2021-44228"`, "example.com/mod"),
		"GO-2021-0001.json":        advisory("GO-2021-0001", `"CVE-2021-44228","GHSA-aaaa-bbbb-cccc"`, "example.com/mod"),
		"NOCVE-1.json":             advisory("NOCVE-1", ``, "example.com/other"),
		"broken.json":              `{"id":`,
		"again/GO-2021-0001.json":  advisory("GO-2021-0001", ``, "example.com/dup"),
		"README.txt":               "not an advisory",
	})

	applied, err := syncOSV(t, db, "Go", archive)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Records != 3 || applied.Skipped != 2 {
		t.Errorf("records=%d skipped=%d, want 3 and 2 (one broken, one repeated id)", applied.Records, applied.Skipped)
	}
	if n := count(t, db, "osv_advisory"); n != 3 {
		t.Errorf("osv_advisory rows = %d, want 3", n)
	}

	var d *Detail
	if err := db.InTx(context.Background(), func(tx *sql.Tx) error {
		var err error
		d, err = Show(context.Background(), tx, "GHSA-aaaa-bbbb-cccc")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !d.Known || d.CVE != "CVE-2021-44228" || d.Via != "GHSA-aaaa-bbbb-cccc" {
		t.Fatalf("a GHSA id did not resolve to its CVE: %+v", d)
	}
	if len(d.Advisories) != 2 || len(d.Advisories[0].Packages) != 1 {
		t.Errorf("advisories = %+v, want the two that name the CVE", d.Advisories)
	}
	if !strings.Contains(strings.Join(d.Aliases, " "), "GO-2021-0001") {
		t.Errorf("aliases = %v, want the Go advisory id among them", d.Aliases)
	}

	var unknown *Detail
	_ = db.InTx(context.Background(), func(tx *sql.Tx) error {
		unknown, _ = Show(context.Background(), tx, "GHSA-nope")
		return nil
	})
	if unknown == nil || unknown.Known {
		t.Errorf("an alias nobody has seen was reported as known: %+v", unknown)
	}
}

func TestSyncOSVReplacesOnlyItsOwnEcosystem(t *testing.T) {
	db := testDB(t)

	two := zipOf(t, map[string]string{
		"A.json": advisory("A", `"CVE-2020-0001"`, "m/a"),
		"B.json": advisory("B", `"CVE-2020-0002"`, "m/b"),
	})
	other := zipOf(t, map[string]string{"C.json": advisory("C", `"CVE-2020-0003"`, "m/c")})
	if _, err := syncOSV(t, db, "Go", two); err != nil {
		t.Fatal(err)
	}
	if _, err := syncOSV(t, db, "PyPI", other); err != nil {
		t.Fatal(err)
	}

	// OSV drops advisory B from the Go archive.
	one := zipOf(t, map[string]string{"A.json": advisory("A", `"CVE-2020-0001"`, "m/a")})
	if _, err := syncOSV(t, db, "Go", one); err != nil {
		t.Fatal(err)
	}

	if n := count(t, db, "osv_advisory"); n != 2 {
		t.Errorf("osv_advisory rows = %d, want A from Go and C from PyPI", n)
	}
	var aliases int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT count(*) FROM cve_alias WHERE osv_id = 'B'").Scan(&aliases); err != nil {
		t.Fatal(err)
	}
	if aliases != 0 {
		t.Errorf("a dropped advisory left %d alias rows behind", aliases)
	}
	if n := count(t, db, "osv_affected"); n != 2 {
		t.Errorf("osv_affected rows = %d, want 2", n)
	}
}

func TestSyncOSVRefusesAnEmptyArchive(t *testing.T) {
	db := testDB(t)
	full := zipOf(t, map[string]string{"A.json": advisory("A", `"CVE-2020-0001"`, "m/a")})
	if _, err := syncOSV(t, db, "Go", full); err != nil {
		t.Fatal(err)
	}

	empty := zipOf(t, map[string]string{"notes.txt": "nothing"})
	if _, err := syncOSV(t, db, "Go", empty); err == nil {
		t.Fatal("an archive with no advisories was accepted")
	}
	if n := count(t, db, "osv_advisory"); n != 1 {
		t.Errorf("a refused sync changed the data: %d advisories", n)
	}
	if _, err := syncOSV(t, db, "Go", []byte("not a zip")); err == nil {
		t.Error("a body that is not a zip was accepted")
	}
}

func TestLookupSelectsGroupsAndKeepsOptionalSourcesOut(t *testing.T) {
	def, err := Lookup(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range def {
		if s.Optional {
			t.Errorf("default sync includes optional source %s", s.Name)
		}
	}
	if len(def) != 2 {
		t.Errorf("default sources = %d, want kev and epss", len(def))
	}

	all, err := Lookup([]string{"osv"})
	if err != nil || len(all) != len(osvEcosystems) {
		t.Errorf("osv group = %d sources (%v), want %d", len(all), err, len(osvEcosystems))
	}
	one, err := Lookup([]string{"OSV-Go"})
	if err != nil || len(one) != 1 || one[0].Name != "osv-go" {
		t.Errorf("osv-go = %v (%v)", one, err)
	}
	if _, err := Lookup([]string{"nope"}); err == nil || !strings.Contains(err.Error(), "osv") {
		t.Errorf("an unknown source should list the known ones including groups: %v", err)
	}
}

func TestSyncOSVThroughSyncKeepsAWatermark(t *testing.T) {
	db := testDB(t)
	archive := zipOf(t, map[string]string{"A.json": advisory("A", `"CVE-2020-0001"`, "m/a")})
	srv, downloads := feed(t, archive, `"osv"`)
	src := Source{Name: "osv-go", URL: srv.URL, Group: "osv", Optional: true, apply: applyOSV("Go")}

	res, err := Sync(context.Background(), db, src, Options{Client: srv.Client()})
	if err != nil || res.Records != 1 {
		t.Fatalf("Sync = %+v, %v", res, err)
	}
	res, err = Sync(context.Background(), db, src, Options{Client: srv.Client()})
	if err != nil || !res.NotModified || *downloads != 1 {
		t.Errorf("second sync = %+v, %v, downloads=%d; an unchanged archive should not download again", res, err, *downloads)
	}
}
