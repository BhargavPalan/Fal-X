package intel

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// nvdFixture is a trimmed real NVD 2.0 response for one CVE: a secondary and a
// primary v3.1 metric, a v2 metric, and a Spanish description before the English.
func nvdFixture(id string) string {
	return `{"totalResults":1,"vulnerabilities":[{"cve":{
	 "id":"` + id + `","published":"2023-12-18T16:15:10.897","lastModified":"2026-06-17T06:34:59.200",
	 "vulnStatus":"Modified",
	 "descriptions":[{"lang":"es","value":"texto en espanol"},{"lang":"en","value":"The SSH transport protocol"}],
	 "weaknesses":[{"description":[{"lang":"en","value":"CWE-354"}]},{"description":[{"lang":"en","value":"CWE-354"},{"lang":"en","value":"CWE-20"}]}],
	 "metrics":{
	  "cvssMetricV2":[{"type":"Primary","cvssData":{"version":"2.0","vectorString":"AV:N","baseScore":9.0,"baseSeverity":"HIGH"}}],
	  "cvssMetricV31":[
	   {"type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/SECONDARY","baseScore":7.7,"baseSeverity":"HIGH"}},
	   {"type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N","baseScore":5.9,"baseSeverity":"MEDIUM"}}]
	 }}}]}`
}

func TestParseNVDPrefersNewestVersionAndPrimarySource(t *testing.T) {
	r, err := ParseNVD(strings.NewReader(nvdFixture("CVE-2023-48795")), "cve-2023-48795")
	if err != nil {
		t.Fatal(err)
	}
	if r.CVE != "CVE-2023-48795" || r.Description != "The SSH transport protocol" {
		t.Errorf("identity/description wrong: %+v", r)
	}
	// v3.1 beats v2.0, and the primary assessment beats the secondary one.
	if r.CVSSVersion != "3.1" || r.CVSSScore == nil || *r.CVSSScore != 5.9 || r.CVSSSeverity != "MEDIUM" ||
		!strings.Contains(r.CVSSVector, "AV:N/AC:H") {
		t.Errorf("wrong metric chosen: version=%s score=%v severity=%s", r.CVSSVersion, r.CVSSScore, r.CVSSSeverity)
	}
	if len(r.CWEs) != 2 || r.CWEs[0] != "CWE-354" || r.CWEs[1] != "CWE-20" {
		t.Errorf("CWEs not de-duplicated in order: %v", r.CWEs)
	}
	if r.Published == nil || r.Published.Year() != 2023 {
		t.Errorf("published not parsed: %v", r.Published)
	}
}

func TestParseNVDRefusesTheWrongCVEAndEmptyAnswers(t *testing.T) {
	if _, err := ParseNVD(strings.NewReader(nvdFixture("CVE-2020-0001")), "CVE-2023-48795"); err == nil {
		t.Error("an answer about a different CVE was accepted")
	}
	if _, err := ParseNVD(strings.NewReader(`{"totalResults":0,"vulnerabilities":[]}`), "CVE-2023-48795"); !errors.Is(err, ErrNotInNVD) {
		t.Errorf("empty answer = %v, want ErrNotInNVD", err)
	}
	if _, err := ParseNVD(strings.NewReader(`not json`), "CVE-2023-48795"); err == nil {
		t.Error("garbage accepted")
	}
	// A CVE with no CVSS metrics at all is still a valid record, with no score.
	r, err := ParseNVD(strings.NewReader(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-1","metrics":{}}}]}`), "CVE-2024-1")
	if err != nil || r.CVSSScore != nil {
		t.Errorf("unscored CVE: %v %+v", err, r)
	}
}

// nvdBodies are the responses the fake NVD knows about.
var nvdBodies = map[string]string{
	"CVE-2023-48795": nvdFixture("CVE-2023-48795"),
	"CVE-2021-44228": nvdFixture("CVE-2021-44228"),
	"CVE-2022-0001":  nvdFixture("CVE-2022-0001"),
}

// nvdServer serves per-CVE responses, counts requests, records the key it was
// sent, and refuses every request after the first refuseAfter when that is set.
func nvdServer(t *testing.T, refuseAfter int) (*httptest.Server, *int32, *atomic.Value) {
	t.Helper()
	var hits int32
	var key atomic.Value
	key.Store("")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		key.Store(r.Header.Get("apiKey"))
		if refuseAfter > 0 && int(n) > refuseAfter {
			http.Error(w, "slow down", http.StatusForbidden)
			return
		}
		// Only known fixtures are served, like the real API answering for ids it
		// has; anything else is "not found".
		body, ok := nvdBodies[r.URL.Query().Get("cveId")]
		if !ok {
			body = `{"totalResults":0,"vulnerabilities":[]}`
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits, &key
}

func TestEnrichNVDStoresSkipsFreshAndReportsNotFound(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	srv, hits, key := nvdServer(t, 0)
	opts := NVDOptions{BaseURL: srv.URL, Client: srv.Client(), Delay: time.Millisecond, APIKey: "secret-key"}

	got := map[string]string{}
	opts.Progress = func(id, outcome string) { got[id] = outcome }
	ids := []string{"CVE-2023-48795", "cve-2021-44228", "CVE-2099-0001", "not-a-cve"}
	res, err := EnrichNVD(ctx, db, ids, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Fetched != 2 || res.NotInNVD != 1 || res.Fresh != 0 {
		t.Errorf("first run: %+v", res)
	}
	if got["CVE-2099-0001"] != OutcomeNotInNVD || got["CVE-2021-44228"] != OutcomeFetched {
		t.Errorf("progress outcomes: %v", got)
	}
	if got, _ := key.Load().(string); got != "secret-key" {
		t.Errorf("API key not sent as the apiKey header: %q", key.Load())
	}
	if atomic.LoadInt32(hits) != 3 {
		t.Errorf("requests = %d, want 3 (the invalid id must not be sent)", atomic.LoadInt32(hits))
	}
	if count(t, db, "cve_nvd") != 2 {
		t.Errorf("cve_nvd rows = %d, want 2", count(t, db, "cve_nvd"))
	}

	// Records fetched just now are fresh: nothing is requested again.
	before := atomic.LoadInt32(hits)
	res, err = EnrichNVD(ctx, db, []string{"CVE-2023-48795", "CVE-2021-44228"}, opts)
	if err != nil || res.Fresh != 2 || res.Fetched != 0 || atomic.LoadInt32(hits) != before {
		t.Errorf("fresh records were refetched: %+v err=%v hits %d->%d", res, err, before, atomic.LoadInt32(hits))
	}
	// Force ignores freshness.
	opts.Force = true
	if res, err = EnrichNVD(ctx, db, []string{"CVE-2023-48795"}, opts); err != nil || res.Fetched != 1 {
		t.Errorf("forced refetch: %+v err=%v", res, err)
	}

	var d *Detail
	_ = db.InTx(ctx, func(tx *sql.Tx) error {
		d, _ = Show(ctx, tx, "CVE-2023-48795")
		return nil
	})
	if d.NVD == nil || d.NVD.CVSSScore == nil || *d.NVD.CVSSScore != 5.9 || d.NVD.Description == "" {
		t.Errorf("Show does not carry the NVD record: %+v", d.NVD)
	}
}

func TestEnrichNVDStopsOnRateLimitAndKeepsProgress(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	srv, _, _ := nvdServer(t, 1) // the second request is refused
	opts := NVDOptions{BaseURL: srv.URL, Client: srv.Client(), Delay: time.Millisecond}

	res, err := EnrichNVD(ctx, db, []string{"CVE-2023-48795", "CVE-2021-44228", "CVE-2022-0001"}, opts)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	if res.Fetched != 1 || count(t, db, "cve_nvd") != 1 {
		t.Errorf("progress before the refusal was lost: %+v rows=%d", res, count(t, db, "cve_nvd"))
	}
	if !strings.Contains(err.Error(), "NVD_API_KEY") {
		t.Errorf("the error should say how to get a higher limit: %v", err)
	}
}

func TestEnrichNVDRefusesPlainHTTP(t *testing.T) {
	db := testDB(t)
	if _, err := EnrichNVD(context.Background(), db, []string{"CVE-2023-48795"},
		NVDOptions{BaseURL: "http://example.invalid/x"}); err == nil {
		t.Error("a non-https endpoint was accepted")
	}
}
