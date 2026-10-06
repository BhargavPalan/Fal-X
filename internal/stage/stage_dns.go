package stage

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/run"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// Roots collects the authoritative root domains for the run.
//
// The seeds were validated during the precheck, but scope is re-checked here so
// the stage is safe to invoke on its own.
func Roots(ctx context.Context, e *Env) error {
	if e.Opts.IPMode {
		e.Run.SetNote("roots", "IP mode, there is no domain to expand")
		return run.ErrSkip
	}

	out := e.Paths.Roots()

	seeds := e.Opts.Seeds()
	e.Run.SetInputs(len(seeds))

	var raw []string
	for _, seed := range seeds {
		if e.Gate.Scope().Gate(seed, "") {
			raw = append(raw, seed)
			continue
		}
		logging.Debug("roots: seed outside scope: %s", seed)
	}

	// Reverse whois via amass, when an org name and the tool are both present.
	if e.Opts.Org != "" && e.Opts.Amass {
		if !e.Tools.Available("amass") {
			logging.Warn("--deep requested for reverse whois but amass is not installed")
			e.Run.SetNote("roots", "amass missing, reverse-whois skipped")
		} else {
			for _, s := range raw {
				// amass contacts third-party WHOIS services. This is passive
				// data retrieval about a domain the operator already authorized,
				// but it still leaves the machine, so it is gated like anything
				// else.
				if !e.Gate.Scope().Gate(s, "") {
					continue
				}
				logging.Info("reverse whois via amass intel for %s", s)
				lines, err := runLines(ctx, e, "amass", "intel", "-whois", "-d", s)
				if err != nil {
					logging.Debug("roots: amass intel for %s failed: %v", s, err)
					continue
				}
				raw = append(raw, lines...)
			}
		}
	}

	// Normalise, then keep only names the allowlist authorizes.
	//
	// amass output is untrusted: it contains free-form text and occasionally
	// URLs, so every entry is validated as a hostname before it is considered.
	// Whitespace is stripped because amass aligns its output with padding.
	var candidates []string
	seen := make(map[string]struct{})
	for _, line := range raw {
		d := strings.TrimSpace(stripAllSpace(line))
		if d == "" {
			continue
		}
		d = strings.ToLower(d)
		d = strings.TrimSuffix(d, ".")
		if !util.ValidDomain(d) {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		candidates = append(candidates, d)
	}

	if len(candidates) == 0 {
		logging.Warn("no valid root domains")
		e.Run.SetNote("roots", "no valid roots")
		// A present empty file: the stage ran and found nothing.
		return util.WriteLines(out, nil)
	}

	var kept []string
	for _, d := range candidates {
		if e.Gate.Scope().Gate(d, "") {
			kept = append(kept, d)
		} else {
			logging.Debug("roots: %s is outside scope", d)
		}
	}
	sort.Strings(kept)

	if err := util.WriteLines(out, kept); err != nil {
		return err
	}
	e.Run.RecordOutputs("roots", out)

	logging.Ok("roots: %d root domain(s)", len(kept))
	if len(kept) == 0 {
		e.Run.SetNote("roots", "all roots were out of scope")
		return fmt.Errorf("every root domain was refused by the scope allowlist")
	}
	return nil
}

// Subs enumerates subdomains under the roots.
//
// Collectors run concurrently and each writes its own file, so a crash in one
// cannot truncate the merge. A collector that found nothing still leaves a
// present empty file, which is different from one that never ran.
func Subs(ctx context.Context, e *Env) error {
	if e.Opts.IPMode {
		e.Run.SetNote("subs", "IP mode, there is no domain to expand")
		return run.ErrSkip
	}

	roots, ok := util.ReadLines(e.Paths.Roots())
	if !ok || len(roots) == 0 {
		logging.Warn("no roots to enumerate against")
		e.Run.SetNote("subs", "no roots available")
		return util.WriteLines(e.Paths.Subs(), nil)
	}
	e.Run.SetInputs(len(roots))
	logging.Info("enumerating subdomains across %d root domain(s)", len(roots))

	collectors := []struct {
		name string
		fn   func(context.Context, *Env, []string) ([]string, error)
	}{
		{"subfinder", collectSubfinder},
		{"amass", collectAmass},
		{"crtsh", collectCRTSh},
		{"brute", collectBrute},
	}

	// Each collector writes its own file. A collector that panics or is
	// cancelled still leaves the file present, so the merge below never has to
	// distinguish "nothing found" from "never ran" by absence.
	type result struct {
		name  string
		lines []string
		err   error
	}
	results := make(chan result, len(collectors))

	for _, c := range collectors {
		go func(c struct {
			name string
			fn   func(context.Context, *Env, []string) ([]string, error)
		}) {
			defer func() {
				if rec := recover(); rec != nil {
					results <- result{name: c.name, err: fmt.Errorf("collector panicked: %v", rec)}
				}
			}()
			lines, err := safeCollect(ctx, c.fn, e, roots)
			results <- result{name: c.name, lines: lines, err: err}
		}(c)
	}

	var raw []string
	for range collectors {
		r := <-results
		path := filepath.Join(e.Paths.SubsDir, "_col_"+r.name+".txt")

		if r.err != nil {
			logging.Debug("subs: collector %s: %v", r.name, r.err)
			// Recorded as a present empty file so the merge below is total.
			_ = util.WriteLines(path, nil)
			continue
		}
		if err := util.WriteLines(path, r.lines); err != nil {
			return err
		}
		raw = append(raw, r.lines...)
	}

	// Normalise. Tool output is free-form: it contains log lines, URLs and
	// commentary, so anything that is not a hostname is dropped rather than
	// passed downstream where it would fail a later stage confusingly.
	candidates := normaliseHosts(raw)

	// Restrict to the roots being scanned. An out-of-scope discovery under an
	// in-scope root is kept separately rather than discarded: it is a real
	// finding about the estate, not noise.
	inRoots := restrictToRoots(candidates, roots)

	var inScope, outOfScope []string
	for _, h := range inRoots {
		if e.Gate.Scope().Gate(h, "") {
			inScope = append(inScope, h)
		} else {
			outOfScope = append(outOfScope, h)
		}
	}

	rejectedPath := e.Paths.Rejected()
	if err := util.WriteLines(e.Paths.Subs(), inScope); err != nil {
		return err
	}
	if err := util.WriteLines(rejectedPath, outOfScope); err != nil {
		return err
	}
	e.Run.RecordOutputs("subs", e.Paths.Subs(), rejectedPath)

	logging.Ok("subs: %d in scope, %d out of scope", len(inScope), len(outOfScope))
	if len(outOfScope) > 0 {
		logging.Debug("subs: out-of-scope hosts written to %s", rejectedPath)
	}

	if len(inScope) == 0 {
		e.Run.SetNote("subs", "no in-scope subdomains found")
		return fmt.Errorf("subdomain enumeration produced no in-scope results")
	}
	return nil
}

// collectSubfinder runs subfinder over the roots.
func collectSubfinder(ctx context.Context, e *Env, roots []string) ([]string, error) {
	if !e.Tools.Available("subfinder") {
		return nil, fmt.Errorf("subfinder not installed")
	}
	return runLines(ctx, e, "subfinder",
		"-silent", "-all", "-timeout", "20",
		"-t", itoa(e.Opts.Threads),
		"-dL", e.Paths.Roots())
}

// collectAmass runs amass in passive mode, one root at a time.
//
// amass queries third-party resolvers, so each root is gated before it is used.
func collectAmass(ctx context.Context, e *Env, roots []string) ([]string, error) {
	if !e.Opts.Amass {
		return nil, nil
	}
	if !e.Tools.Available("amass") {
		return nil, fmt.Errorf("amass not installed")
	}

	var out []string
	for _, d := range roots {
		if !e.Gate.Scope().Gate(d, "") {
			continue
		}
		lines, err := runLines(ctx, e, "amass", "enum", "-passive", "-timeout", "2", "-d", d)
		if err != nil {
			logging.Debug("subs: amass enum for %s failed: %v", d, err)
			continue
		}
		out = append(out, lines...)
	}
	return out, nil
}

// collectBrute runs DNS brute force, which is opt-in.
func collectBrute(ctx context.Context, e *Env, roots []string) ([]string, error) {
	if !e.Opts.Brute {
		return nil, nil
	}
	if !e.Tools.Available("puredns") {
		logging.Warn("brute force requested but puredns is not installed")
		return nil, fmt.Errorf("puredns not installed")
	}

	args := []string{"bruteforce", e.Opts.DNSWordlist, "-l", e.Paths.Roots()}

	// puredns is given a resolver list. Without one it falls back to the system
	// resolver and becomes dramatically slower and less reliable.
	if _, ok := util.ReadLines(e.Opts.ResolverList); ok {
		args = append(args, "-r", e.Opts.ResolverList)
	} else {
		logging.Warn("no resolver list at %s; puredns will be slow", e.Opts.ResolverList)
		e.Run.SetNote("subs", "resolver list missing")
	}

	return runLines(ctx, e, "puredns", args...)
}

// restrictToRoots keeps only names that sit under one of the roots.
//
// The comparison is label-aware. A substring test would let
// "example.com.attacker.test" through when scanning example.com, which is the
// whole reason the scope gate does not use one.
func restrictToRoots(candidates, roots []string) []string {
	var out []string
	for _, h := range candidates {
		for _, r := range roots {
			if labelUnder(h, r) {
				out = append(out, h)
				break
			}
		}
	}
	return out
}

// labelUnder reports whether host is root or a subdomain of root.
func labelUnder(host, root string) bool {
	if host == root {
		return true
	}
	if len(host) <= len(root)+1 {
		return false
	}
	if !strings.HasSuffix(host, root) {
		return false
	}
	// The character before the suffix must be the label separator, which is
	// what stops "notexample.com" matching "example.com".
	return host[len(host)-len(root)-1] == '.'
}

// normaliseHosts extracts and canonicalises hostnames from free-form output.
func normaliseHosts(lines []string) []string {
	seen := make(map[string]struct{}, len(lines))
	var out []string

	for _, line := range lines {
		// Tool output is frequently a whole line of commentary with the host
		// embedded, so each whitespace-separated token is considered.
		for _, field := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '\r' || r == ',' || r == '"' || r == '\''
		}) {
			h := strings.ToLower(strings.Trim(field, "."))
			h = strings.TrimPrefix(h, "*.")
			if !util.ValidDomain(h) {
				continue
			}
			if _, dup := seen[h]; dup {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// Resolve turns candidate names into verified live hosts.
//
// A name that does not resolve must not be treated as a host: passing
// unverified names into the port scanner produces results that look real but are
// not. So when the resolver is missing the stage fails rather than falling back.
func Resolve(ctx context.Context, e *Env) error {
	out := e.Paths.Resolved()
	ipsPath := filepath.Join(e.Paths.ResolveDir, "ips.txt")
	dnsPath := filepath.Join(e.Paths.ResolveDir, "dns.txt")

	// The roots belong in the resolved set too, kept separate from the
	// subdomain list rather than folded into it.
	candidates, _ := util.ReadLines(e.Paths.Subs())
	roots, _ := util.ReadLines(e.Paths.Roots())

	all := append(append([]string{}, candidates...), roots...)
	candidatesPath := filepath.Join(e.Paths.ResolveDir, "candidates.txt")
	if err := util.WriteLines(candidatesPath, all); err != nil {
		return err
	}
	if err := util.Clean(candidatesPath); err != nil {
		return err
	}
	all, _ = util.ReadLines(candidatesPath)

	if len(all) == 0 {
		logging.Warn("nothing to resolve")
		e.Run.SetNote("resolve", "no candidates")
		// Present empty files for every output, so the manifest shows the stage
		// ran.
		return writeResolveOutputs(out, ipsPath, dnsPath, nil, nil, nil)
	}
	e.Run.SetInputs(len(all))

	if !e.Tools.Available("dnsx") {
		logging.Warn("dnsx is not installed; DNS resolution skipped")
		e.Run.SetNote("resolve", "dnsx missing, hosts NOT verified")
		if err := writeResolveOutputs(out, ipsPath, dnsPath, nil, nil, nil); err != nil {
			return err
		}
		return fmt.Errorf("dnsx is not installed, so no host could be verified")
	}

	// Scope-gate every candidate immediately before the resolver runs. The
	// resolver consumes a file, so the gated list is written first.
	gatedPath := filepath.Join(e.Paths.ResolveDir, "candidates.scoped.txt")
	var gated []string
	for _, h := range all {
		if e.Gate.Scope().Gate(h, "") {
			gated = append(gated, h)
		}
	}
	if err := util.WriteLines(gatedPath, gated); err != nil {
		return err
	}

	if len(gated) == 0 {
		logging.Warn("no candidates survived the scope filter")
		e.Run.SetNote("resolve", "all candidates out of scope")
		return writeResolveOutputs(out, ipsPath, dnsPath, nil, nil, nil)
	}

	logging.Info("resolving %d name(s) with dnsx", len(gated))

	res, err := e.Tools.Run(ctx, "dnsx", "-silent", "-t", itoa(e.Opts.Threads), "-l", gatedPath)
	if err != nil {
		// Surfaced rather than discarded: a silent empty result looks
		// identical to "no subdomains resolve".
		logging.Error("dnsx: %v", err)
		e.Run.SetNote("resolve", "dnsx failed")
	}

	hosts := normaliseHosts(splitLines(res.Stdout))

	// Full record dump for the later stages: A, AAAA, CNAME, NS, MX, TXT. This
	// is what dangling-record and takeover analysis reads.
	var addresses []string
	var records []string
	if len(hosts) > 0 {
		dnsRes, dnsErr := e.Tools.Run(ctx, "dnsx",
			"-silent", "-nc", "-l", e.Paths.Resolved(),
			"-a", "-aaaa", "-cname", "-ns", "-mx", "-resp", "-resp-only")
		if dnsErr != nil {
			logging.Debug("resolve: record dump failed: %v", dnsErr)
		}
		records = splitLines(dnsRes.Stdout)
		addresses = extractAddresses(records)

		// Fall back to a per-host lookup when the combined dump produced
		// nothing, so the address list is not silently empty.
		if len(addresses) == 0 {
			logging.Debug("resolve: falling back to per-host address lookup")
			for _, h := range hosts {
				r, err := e.Tools.Run(ctx, "dnsx", "-silent", "-t", itoa(e.Opts.Threads),
					"-a", "-aaaa", "-resp-only", h)
				if err != nil {
					continue
				}
				addresses = append(addresses, extractAddresses(splitLines(r.Stdout))...)
			}
		}
	}

	// Every extracted address must itself be in scope before a scanner sees it.
	var scopedIPs []string
	seenIP := make(map[string]struct{})
	for _, ip := range addresses {
		if _, dup := seenIP[ip]; dup {
			continue
		}
		if e.Gate.Scope().Gate(ip, "") {
			seenIP[ip] = struct{}{}
			scopedIPs = append(scopedIPs, ip)
		} else {
			logging.Debug("resolve: address outside scope: %s", ip)
		}
	}
	sort.Strings(scopedIPs)

	if err := writeResolveOutputs(out, ipsPath, dnsPath, hosts, scopedIPs, records); err != nil {
		return err
	}
	e.Run.RecordOutputs("resolve", out, ipsPath, dnsPath)

	if len(hosts) == 0 {
		logging.Warn("no names resolved to an address")
		e.Run.SetNote("resolve", "zero hosts resolved")
		return fmt.Errorf("no candidate name resolved to an address")
	}

	logging.Ok("resolve: %d live host(s), %d address(es)", len(hosts), len(scopedIPs))
	return nil
}

// writeResolveOutputs writes the three resolve artifacts, always creating each
// one.
//
// A missing file means the stage never got that far; an empty one means it ran
// and found nothing. That difference is the whole point, so all three are
// created on every path.
func writeResolveOutputs(hosts, ips, dns string, hostList, ipList, recordList []string) error {
	for _, pair := range []struct {
		path  string
		lines []string
	}{
		{hosts, hostList},
		{ips, ipList},
		{dns, recordList},
	} {
		if err := util.WriteLines(pair.path, pair.lines); err != nil {
			return err
		}
	}
	return nil
}

// extractAddresses pulls A and AAAA answers out of a dnsx record dump.
//
// Both address families are handled. A dual-stack host has one of each, and every
// downstream consumer needs both.
func extractAddresses(records []string) []string {
	var out []string
	for _, line := range records {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		recordType := strings.Trim(fields[1], "[]")
		if recordType != "A" && recordType != "AAAA" {
			continue
		}
		candidate := strings.Trim(fields[len(fields)-1], "[]")
		if _, err := netip.ParseAddr(candidate); err != nil {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

// runLines runs a tool and returns its non-blank stdout lines.
func runLines(ctx context.Context, e *Env, name string, args ...string) ([]string, error) {
	res, err := e.Tools.Run(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	return splitLines(res.Stdout), nil
}

// splitLines splits tool output into non-blank lines.
func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(strings.Trim(l, "\r"))
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// stripAllSpace removes every whitespace character.
func stripAllSpace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}

// itoa renders an int.
func itoa(n int) string { return strconv.Itoa(n) }
