package prioritize

import (
	"fmt"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/util"
)

// RenderMarkdown renders ranked findings as a document to hand to someone.
//
// It carries every derivation, so a reader can audit any score without running
// anything, and it says plainly when it shows only part of the list. Asset names,
// templates and details come from scanned hosts, so they pass through
// util.MarkdownText and cannot become markup.
//
// total is how many findings exist; ranked may be a prefix of them.
func RenderMarkdown(ranked []Ranked, total int, generated time.Time) []byte {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("# Fal-X prioritised findings\n\n")
	w("Generated %s.\n\n", generated.UTC().Format("2006-01-02 15:04 UTC"))

	if len(ranked) == 0 {
		w("No findings are stored, so there is nothing to rank.\n")
		return []byte(b.String())
	}

	counts := map[string]int{}
	for _, r := range ranked {
		counts[r.Result.Decision]++
	}
	w("**%d** %s, **%d** %s, **%d** %s",
		counts[Act], Act, counts[Attend], Attend, counts[Track], Track)
	if len(ranked) < total {
		w(" (showing %d of %d findings)", len(ranked), total)
	}
	w(".\n\n")
	w("*Act* means the CVE is on CISA's Known Exploited Vulnerabilities list. *Attend* means an EPSS " +
		"probability of at least 0.5 or a score of at least 50. Everything else is *Track*. This is a " +
		"simplified reading, not CISA's full decision tree.\n\n")

	w("## Ranking\n\n| # | Score | Decision | Asset | Severity | Finding |\n|---|---|---|---|---|---|\n")
	for i, r := range ranked {
		w("| %d | %d | %s | %s | %s | %s |\n", i+1, r.Result.Score, r.Result.Decision,
			util.MarkdownText(r.Asset), util.MarkdownText(r.Finding.Severity),
			util.MarkdownText(r.Finding.Template))
	}

	w("\n## How each score was reached\n\n")
	for i, r := range ranked {
		w("### %d. %s on %s (%d, %s)\n\n", i+1,
			util.MarkdownText(r.Finding.Template), util.MarkdownText(r.Asset),
			r.Result.Score, r.Result.Decision)
		for _, why := range r.Result.Why {
			w("- %+d %s: %s\n", why.Points, util.MarkdownText(why.Signal), util.MarkdownText(why.Detail))
		}
		w("\n")
	}
	return []byte(b.String())
}
