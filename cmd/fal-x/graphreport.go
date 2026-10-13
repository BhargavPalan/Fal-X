package main

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

// renderGraphReport renders the entity graph and the ranked findings as a Markdown
// document, read from the database. It is the shareable artifact a scan produces now
// that scans write the graph rather than per-stage files.
func renderGraphReport(ctx context.Context, db *store.DB) ([]byte, error) {
	var b strings.Builder
	err := db.InTx(ctx, func(tx *sql.Tx) error {
		counts, err := graph.CountByType(ctx, tx)
		if err != nil {
			return err
		}
		inv, err := graph.Inventory(ctx, tx)
		if err != nil {
			return err
		}
		ranked, err := prioritize.RankAll(ctx, tx)
		if err != nil {
			return err
		}

		b.WriteString("# Attack surface\n\n")
		fmt.Fprintf(&b, "_generated %s_\n\n", time.Now().UTC().Format(time.RFC3339))

		writeGraphSummary(&b, counts)
		facts, byType := indexInventory(inv)
		writeEntityList(&b, "Hosts", byType["host"], facts, "host", []string{"server"})
		writeEntityList(&b, "Services", byType["service"], facts, "service", nil)
		writeEntityList(&b, "Certificates", byType["certificate"], facts, "certificate", []string{"subject_cn", "issuer", "not_after"})
		writeEntityList(&b, "Emails", byType["email"], facts, "email", nil)
		writeFindings(&b, ranked)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// entKey identifies one entity across the flat inventory rows.
type entKey struct{ typ, key string }

// indexInventory groups the flat inventory into a fact lookup and a per-type list of
// entity keys, both deterministic.
func indexInventory(inv []graph.InvRow) (map[entKey]map[string]string, map[string][]string) {
	facts := map[entKey]map[string]string{}
	byType := map[string][]string{}
	for _, r := range inv {
		k := entKey{r.EntityType, r.EntityKey}
		if _, ok := facts[k]; !ok {
			facts[k] = map[string]string{}
			byType[r.EntityType] = append(byType[r.EntityType], r.EntityKey)
		}
		if r.FactKey != "" {
			facts[k][r.FactKey] = r.FactValue
		}
	}
	for _, list := range byType {
		sort.Strings(list)
	}
	return facts, byType
}

func writeGraphSummary(b *strings.Builder, counts map[graph.EntityType]int) {
	b.WriteString("## Summary\n\n")
	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, string(t))
	}
	sort.Strings(types)
	for _, t := range types {
		fmt.Fprintf(b, "- %s: %d\n", t, counts[graph.EntityType(t)])
	}
	b.WriteString("\n")
}

// writeEntityList writes one section listing entities of a type, with selected facts
// appended for context.
func writeEntityList(b *strings.Builder, title string, keys []string, facts map[entKey]map[string]string, typ string, show []string) {
	if len(keys) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s (%d)\n\n", title, len(keys))
	for _, key := range keys {
		line := key
		var extra []string
		for _, fk := range show {
			if v := facts[entKey{typ, key}][fk]; v != "" {
				extra = append(extra, v)
			}
		}
		if len(extra) > 0 {
			line += " — " + strings.Join(extra, ", ")
		}
		fmt.Fprintf(b, "- %s\n", line)
	}
	b.WriteString("\n")
}

// writeFindings writes the ranked CVE findings, most urgent first.
func writeFindings(b *strings.Builder, ranked []prioritize.Ranked) {
	b.WriteString("## Findings\n\n")
	if len(ranked) == 0 {
		b.WriteString("No matched vulnerabilities. Run `fal-x intel sync` and `fal-x match` if this is unexpected.\n\n")
		return
	}
	b.WriteString("| # | Score | Decision | Asset | Severity | Finding |\n")
	b.WriteString("|---|------:|----------|-------|----------|---------|\n")
	for i, r := range ranked {
		fmt.Fprintf(b, "| %d | %d | %s | %s | %s | %s |\n",
			i+1, r.Result.Score, r.Result.Decision, r.Asset, r.Finding.Severity, r.Finding.Template)
	}
	b.WriteString("\n")
}
