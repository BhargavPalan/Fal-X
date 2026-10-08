package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/tools"
)

// execLookPath resolves a tool on PATH, returning the candidate path.
//
// The plan needs to know whether a tool is installed before deciding whether to
// warn about it. It returns a path that may not exist, so a caller must stat it
// rather than test for a non-empty string.
func execLookPath(tool string) (string, error) { return tools.Resolve(tool) }

// filepathJoin is a thin alias so this file does not import path/filepath under
// a name that shadows the local variables used here.
func filepathJoin(parts ...string) string { return filepath.Join(parts...) }

// now returns the current time, indirected so a test can pin it.
var now = time.Now

// joinComma renders names for a message.
//
// An empty list reads as "none", because this reaches a human and a bare blank
// would look like output had been truncated. internal/run has the same shape for
// a summary suffix, where an empty list should contribute nothing instead.
func joinComma(names []string) string {
	switch len(names) {
	case 0:
		return "none"
	case 1:
		return names[0]
	}
	return strings.Join(names, ", ")
}

// scanFlags is the orientation aid printed by `fal-x scan --help`.
//
// The authoritative list lives in internal/cli. Reusing the flag package here
// would mean either registering every flag twice or inventing names it rejects,
// so this is a plain table.
var scanFlags = [][2]string{
	{"-d <domain>", "target domain, comma-separated list, or a file of domains"},
	{"-l <file>", "file with one domain per line"},
	{"-ip <ip|cidr>", "scan addresses or ranges, skipping domain discovery"},
	{"-asn <AS>", "enumerate an autonomous system into netblocks"},

	{"--scope <file>", "restrict the run to these targets. Optional; without it every target is reachable"},
	{"--exclude <file>", "denylist, applied after the allowlist"},
	{"--allow-private", "permit private, loopback and link-local ranges inside a scope file"},
	{"--allow-any", "permit a bare wildcard in the scope file"},
	{"--yes", "answer the wide-target confirmation without prompting"},
	{"--why-denied <target>", "explain the scope decision for one target and exit"},
	{"--dry-run", "validate inputs and print the plan. Contacts nothing"},

	{"--profile <name>", "fast, normal or exhaustive"},
	{"--stages <list>", "comma-separated subset of the pipeline stages"},
	{"--skip-scan", "omit the vulnerability scanning stage"},
	{"--ports <spec>", "ports to scan, for example 80,443 or 8000-8100"},
	{"--output <dir>", "output root. Defaults to ./output"},
	{"--env-file <file>", "credential file. Parsed as data, never sourced"},

	// These send real traffic beyond what the operator asked for, so they are
	// grouped where they can be found rather than buried.
	{"--brute", "enable DNS brute force"},
	{"--dirs", "brute-force directories with ffuf"},
	{"--deep", "add amass passive enumeration"},
	{"--nmap", "run nmap service detection on open ports"},
	{"--censys", "passive Censys enrichment. Needs a token in config/.env"},
}

// scanUsage renders the scan usage text.
func scanUsage() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage:\n")
	fmt.Fprintf(&b, "  fal-x scan -d <domain>  --scope <file> [flags]\n")
	fmt.Fprintf(&b, "  fal-x scan -l <file>    --scope <file> [flags]\n")
	fmt.Fprintf(&b, "  fal-x scan -ip <ip|cidr> --scope <file> [flags]\n")
	fmt.Fprintf(&b, "  fal-x scan -asn <AS>    --scope <file> [flags]\n\n")
	fmt.Fprintf(&b, "Exactly one target. An active run requires a readable allowlist, which\n")
	fmt.Fprintf(&b, "is checked before anything is contacted. A target reaching much further\n")
	fmt.Fprintf(&b, "than its name suggests asks to be confirmed.\n\nFlags:\n")

	width := 0
	for _, f := range scanFlags {
		if len(f[0]) > width {
			width = len(f[0])
		}
	}
	for _, f := range scanFlags {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, f[0], f[1])
	}

	fmt.Fprintf(&b, "\nRun with --dry-run to see the effective scope before scanning anything.\n")
	return b.String()
}
