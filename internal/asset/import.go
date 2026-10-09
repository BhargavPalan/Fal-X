// Package asset turns a finished run into inventory.
//
// It reads a run directory through internal/report, so there is one parser for
// each stage's output and a report and the database can never disagree about what
// a run found. It writes through internal/store inside a single transaction that
// runs as one tenant, so a half-imported run is never visible.
//
// Everything a run found is kept: subdomains, resolved hosts, addresses, open
// services, live URLs, crawled URLs, and every finding. Nothing is trimmed to
// save rows.
package asset

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/report"
	"github.com/BhargavPalan/Fal-X/internal/store"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// The asset kinds the schema allows.
const (
	KindDomain  = "domain"
	KindHost    = "host"
	KindIP      = "ip"
	KindURL     = "url"
	KindService = "service"
)

// Summary says what an import wrote.
type Summary struct {
	RunID        string
	Assets       int
	Attributes   int
	Observations int
	Findings     int
}

// Import persists the run in dir for the organization with the given slug.
//
// It is idempotent. Importing the same run again updates it in place, so a
// scan that auto-persisted can be imported again by hand without duplicates.
func Import(ctx context.Context, db *store.DB, orgSlug, dir string) (Summary, error) {
	m, err := report.Load(dir)
	if err != nil {
		return Summary{}, err
	}
	if err := validateModel(m); err != nil {
		return Summary{}, err
	}
	orgID, err := db.EnsureOrg(ctx, orgSlug, orgSlug)
	if err != nil {
		return Summary{}, err
	}

	scoped, err := db.WithOrg(ctx, orgID)
	if err != nil {
		return Summary{}, err
	}

	var sum Summary
	sum.RunID = m.RunID
	err = scoped.InTx(ctx, func(tx *sql.Tx) error {
		runPK, err := store.UpsertRun(ctx, tx, orgID, runRecord(m), scopeRecord(m), stageRecords(m))
		if err != nil {
			return err
		}
		w := &writer{
			tx: tx, orgID: orgID, runPK: runPK, sum: &sum,
			seenAssets: map[string]bool{}, seenObs: map[string]bool{}, seenAttrs: map[string]bool{},
		}
		return w.write(ctx, m)
	})
	if err != nil {
		return Summary{}, err
	}
	return sum, nil
}

// writer carries the state of one import transaction.
type writer struct {
	tx    *sql.Tx
	orgID int64
	runPK int64
	sum   *Summary

	// seenAssets and seenObs count what was written once each. A URL that the
	// crawl, the endpoint list and a finding all name is one asset, and the
	// summary must say so rather than report three.
	seenAssets map[string]bool
	seenObs    map[string]bool
	seenAttrs  map[string]bool
}

// see upserts an asset and records that this run observed it at a stage.
func (w *writer) see(ctx context.Context, kind, identifier, stage string) (int64, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return 0, nil
	}
	id, err := store.UpsertAsset(ctx, w.tx, w.orgID, kind, identifier)
	if err != nil {
		return 0, err
	}
	if !w.seenAssets[kind+" "+identifier] {
		w.seenAssets[kind+" "+identifier] = true
		w.sum.Assets++
	}
	if err := store.Observe(ctx, w.tx, id, w.runPK, stage); err != nil {
		return 0, err
	}
	if key := fmt.Sprint(id, " ", stage); !w.seenObs[key] {
		w.seenObs[key] = true
		w.sum.Observations++
	}
	return id, nil
}

// attr records a fact about an asset.
func (w *writer) attr(ctx context.Context, id int64, key, value, source string) error {
	if id == 0 || strings.TrimSpace(value) == "" {
		return nil
	}
	if err := store.AddAttribute(ctx, w.tx, id, key, value, source, 1.0); err != nil {
		return err
	}
	if k := fmt.Sprint(id, " ", key, " ", value); !w.seenAttrs[k] {
		w.seenAttrs[k] = true
		w.sum.Attributes++
	}
	return nil
}

func (w *writer) write(ctx context.Context, m *report.Model) error {
	// Names the run discovered but did not necessarily resolve.
	for _, s := range m.Subdomains.Items {
		if _, err := w.see(ctx, KindDomain, strings.ToLower(s), "subs"); err != nil {
			return err
		}
	}
	// Names that resolved to an address.
	for _, s := range m.Resolved.Items {
		if _, err := w.see(ctx, KindHost, strings.ToLower(s), "resolve"); err != nil {
			return err
		}
	}
	for _, s := range m.Addresses.Items {
		if _, err := w.see(ctx, KindIP, s, "resolve"); err != nil {
			return err
		}
	}
	// host:port pairs that answered.
	for _, s := range m.OpenPorts.Items {
		if _, err := w.see(ctx, KindService, s, "ports"); err != nil {
			return err
		}
	}
	// Live web services, with what the probe learned about each.
	for _, s := range m.Services.Items {
		id, err := w.see(ctx, KindURL, s.URL, "http")
		if err != nil {
			return err
		}
		const src = "http/httpx"
		if s.Status != 0 {
			if err := w.attr(ctx, id, "status", fmt.Sprint(s.Status), src); err != nil {
				return err
			}
		}
		if err := w.attr(ctx, id, "title", s.Title, src); err != nil {
			return err
		}
		if err := w.attr(ctx, id, "server", s.Server, src); err != nil {
			return err
		}
		for _, t := range s.Tech {
			if err := w.attr(ctx, id, "tech", t, src); err != nil {
				return err
			}
		}
	}
	// Everything the crawl turned up. URLs and endpoints are usually the same
	// list; the unique constraint collapses the overlap.
	for _, u := range m.URLs.Items {
		if _, err := w.see(ctx, KindURL, u, "content"); err != nil {
			return err
		}
	}
	for _, u := range m.Endpoints.Items {
		if _, err := w.see(ctx, KindURL, u, "content"); err != nil {
			return err
		}
	}
	// Findings become attributes of the thing they were found on.
	for _, f := range m.Findings.Items {
		kind, ident := findingAsset(f.Target)
		id, err := w.see(ctx, kind, ident, "scan")
		if err != nil {
			return err
		}
		if err := w.attr(ctx, id, "finding", findingValue(f), "scan/nuclei"); err != nil {
			return err
		}
		w.sum.Findings++
	}
	return nil
}

// findingAsset decides which asset a finding belongs to from its target: a URL
// is a url, a host:port is a service, anything else is a host.
func findingAsset(target string) (kind, identifier string) {
	t := strings.TrimSpace(target)
	if u, err := url.Parse(t); err == nil && u.Scheme != "" && u.Host != "" {
		return KindURL, t
	}
	if host, port := util.HostPortSplit(t); host != "" && port != "" {
		return KindService, t
	}
	return KindHost, strings.ToLower(t)
}

// findingValue is the attribute value for a finding: severity, template, and any
// matcher and detail, so two different findings on one asset stay distinct.
func findingValue(f report.Finding) string {
	id := f.Template
	if f.Matcher != "" {
		id += ":" + f.Matcher
	}
	if id == "" {
		return f.Severity + " " + f.Raw
	}
	v := f.Severity + " " + id
	if f.Detail != "" {
		v += " " + f.Detail
	}
	return v
}

func runRecord(m *report.Model) store.Run {
	started, _ := time.Parse(time.RFC3339, m.StartedAt)
	if started.IsZero() {
		started = time.Now().UTC()
	}
	finished := started.Add(time.Duration(m.ElapsedSeconds) * time.Second)

	status := "completed"
	for _, s := range m.Stages {
		if s.Status == "failed" {
			status = "completed_with_failures"
			break
		}
	}
	mode := m.Mode
	if mode == "" {
		mode = "domain" // runs written before the manifest recorded a mode
	}
	tools := "{}"
	if len(m.ToolVersions) > 0 {
		if b, err := json.Marshal(m.ToolVersions); err == nil {
			tools = string(b)
		}
	}
	return store.Run{
		ToolVersions: tools,
		RunID:        m.RunID, Label: m.Target, Mode: mode, Status: status,
		Targets: []string{m.Target}, Profile: orDefault(m.Profile, "normal"),
		StartedAt: started, FinishedAt: &finished, DurationSecs: int(m.ElapsedSeconds),
	}
}

func scopeRecord(m *report.Model) store.Scope {
	allow := m.ScopeDigest
	if allow == "" {
		allow = util.SHA256String(m.ScopeAllowlist)
	}
	deny := ""
	if m.ScopeDenylist != "" {
		deny = util.SHA256String(m.ScopeDenylist)
	}
	return store.Scope{
		AllowlistDigest: allow, DenylistDigest: deny,
		AllowPrivate: m.AllowPrivate, AllowAny: m.AllowAny,
	}
}

func stageRecords(m *report.Model) []store.Stage {
	out := make([]store.Stage, 0, len(m.Stages))
	for i, s := range m.Stages {
		out = append(out, store.Stage{
			Name: s.Name, Seq: i, Status: s.Status, ExitCode: s.ExitCode,
			DurationSecs: int(s.DurationSeconds), Inputs: int64(s.Inputs),
			Outputs: int64(s.Outputs), Note: s.Note,
		})
	}
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// validateModel rejects a run the schema would refuse, with a message that names
// the field. A run bundle can come from anywhere (`assets import --from` takes any
// directory), so a value outside the allowed set must fail clearly here and not as
// a raw check-constraint violation from inside the transaction.
func validateModel(m *report.Model) error {
	if strings.TrimSpace(m.RunID) == "" {
		return errors.New("asset: the run has no run id")
	}
	if strings.TrimSpace(m.Target) == "" {
		return fmt.Errorf("asset: run %s has no target", m.RunID)
	}
	switch m.Mode {
	case "", "domain", "ip", "asn":
	default:
		return fmt.Errorf("asset: run %s has mode %q; the mode must be domain, ip or asn", m.RunID, m.Mode)
	}
	for _, s := range m.Stages {
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("asset: run %s has a stage with no name", m.RunID)
		}
		switch s.Status {
		case "succeeded", "failed", "skipped", "running":
		default:
			return fmt.Errorf("asset: run %s stage %s has status %q; the status must be succeeded, failed, skipped or running",
				m.RunID, s.Name, s.Status)
		}
	}
	return nil
}
