// Package monitor turns a re-scan into change events: it diffs the graph against the
// previous run, classifies what changed by severity, and emits only the transitions a
// prior run has not already reported.
//
// A change report is a query over first_seen_at/last_seen_at, never a file comparison,
// so it is exact and reproducible. The alerting side is deliberately thin — stdout and
// an optional webhook — because the value is in deciding what is worth an alert, not in
// the transport.
package monitor

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/prioritize"
	"github.com/BhargavPalan/Fal-X/internal/store"
)

// ChangeEvent is one reported change on the attack surface.
type ChangeEvent struct {
	Type     string    `json:"type"`     // "added", "gone" or "changed"
	Kind     string    `json:"kind"`     // the entity's type
	Key      string    `json:"key"`      // the entity's identity
	Detail   string    `json:"detail"`   // for a change, the fact that changed
	Severity string    `json:"severity"` // critical, high, medium, low or info
	At       time.Time `json:"at"`
}

// highValueKinds are entity types whose mere appearance is more than informational: a
// new credential, bucket or repository on the surface is a lead, not noise.
var highValueKinds = map[graph.EntityType]bool{
	graph.TypeCredential:    true,
	graph.TypeLeak:          true,
	graph.TypeBucket:        true,
	graph.TypeRepository:    true,
	graph.TypeCloudResource: true,
}

// Events classifies a diff into severity-tagged change events: a new asset or a new fact
// on a known asset. A new finding carries the finding's own severity; a new exposure or a
// confirmed verification is high; a routine new subdomain is informational.
//
// Disappearance ("gone") is deliberately not alerted: with scope and the budget brake, a
// re-scan does not always re-observe every live asset, so "not seen this scan" is not
// "gone" — it would flood false alerts. `fal-x diff` reports gone assets for review.
func Events(added []store.DiffRow, changed []store.DiffFact) []ChangeEvent {
	var out []ChangeEvent
	for _, r := range added {
		sev := "info"
		if highValueKinds[graph.EntityType(r.Kind)] {
			sev = "high"
		}
		out = append(out, ChangeEvent{Type: "added", Kind: r.Kind, Key: r.Identifier, Severity: sev, At: r.FirstSeen})
	}
	for _, f := range changed {
		out = append(out, ChangeEvent{
			Type:     "changed",
			Kind:     f.Kind,
			Key:      f.Identifier,
			Detail:   f.Key + "=" + f.Value,
			Severity: factSeverity(f.Key, f.Value),
		})
	}
	return out
}

// factSeverity rates a newly observed fact. A finding keeps the severity the scanner
// stamped on it; an exposure class or a confirmed verification is high; anything else is
// informational.
func factSeverity(key, value string) string {
	switch key {
	case "finding":
		return prioritize.ParseFinding(value).Severity
	case "exposure":
		return "high"
	case "verification":
		if strings.HasPrefix(value, "confirmed") {
			return "high"
		}
		return "info"
	default:
		return "info"
	}
}

// Cycle is one monitoring tick: it diffs the graph since the previous run and returns the
// change events. `since` must come from the database clock (store.Now), so a scan's own
// inserts are reliably on the far side of the window boundary. No cross-run dedup state is
// kept: the diff window is bounded by `since`, and because each cycle advances `since`, a
// given change falls in exactly one window and is never re-reported.
func Cycle(ctx context.Context, db *store.DB, since time.Time, limit int) ([]ChangeEvent, error) {
	var added []store.DiffRow
	var changed []store.DiffFact
	if err := db.InTx(ctx, func(tx *sql.Tx) error {
		var e error
		added, _, changed, e = store.Diff(ctx, tx, since, limit)
		return e
	}); err != nil {
		return nil, err
	}
	return Events(added, changed), nil
}

// severityRank orders severities so the most urgent change sorts first.
var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}

// Format renders events for a terminal or a log, most severe first. An empty slice
// renders as a single "no changes" line so a quiet run is distinguishable from a run
// that never happened.
func Format(events []ChangeEvent) string {
	if len(events) == 0 {
		return "no changes"
	}
	sorted := append([]ChangeEvent(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityRank[sorted[i].Severity] < severityRank[sorted[j].Severity]
	})
	var b strings.Builder
	for _, e := range sorted {
		line := fmt.Sprintf("[%s] %s %s %s", e.Severity, e.Type, e.Kind, e.Key)
		if e.Detail != "" {
			line += " (" + e.Detail + ")"
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}
