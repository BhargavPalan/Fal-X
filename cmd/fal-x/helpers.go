package main

import (
	"fmt"
	"strings"
	"time"
)

// now is time.Now, replaceable so a test can pin the run stamp.
var now = time.Now

// joinComma renders names for a message. An empty list reads "none": this reaches a
// person, and a bare blank would look like truncated output.
func joinComma(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// scanFlags is the table `fal-x scan --help` prints. The flags themselves are
// declared and validated in internal/cli, so this is orientation, not a second
// source of truth.
var scanFlags = [][2]string{
	{"-d <domain>", "target domain, comma-separated list, or a file of domains"},
	{"-l <file>", "file with one domain per line"},
	{"-ip <ip|cidr>", "scan addresses or ranges, skipping domain discovery"},
	{"-asn <AS>", "enumerate an autonomous system into netblocks"},

	{"--scope <file>", "hold the run to this allowlist. Optional; without it every named target is reachable"},
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

	// These send real traffic beyond what the operator asked for.
	{"--brute", "enable DNS brute force"},
	{"--dirs", "brute-force directories with ffuf"},
	{"--deep", "add amass passive enumeration"},
	{"--nmap", "run nmap service detection on open ports"},
	{"--censys", "passive Censys enrichment. Needs a token in config/.env"},
}

const scanUsageHead = `Usage:
  fal-x scan <target> [flags]
  fal-x scan -d <domain> | -l <file> | -ip <ip|cidr> | -asn <AS> [flags]

Exactly one target. With --scope the run is held to that allowlist and refuses if
it cannot be read; without it every named target is reachable. A target reaching
much further than its name suggests (an autonomous system, a prefix wider than a
/22, a bare wildcard) asks to be confirmed before anything is contacted.

Flags:
`

func scanUsage() string {
	var b strings.Builder
	b.WriteString(scanUsageHead)

	width := 0
	for _, f := range scanFlags {
		width = max(width, len(f[0]))
	}
	for _, f := range scanFlags {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, f[0], f[1])
	}

	b.WriteString("\nRun with --dry-run to see the effective scope before scanning anything.\n")
	return b.String()
}
