package stage

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// HTTP probes hosts for live web services.
//
// It consumes the host:port pairs the port stage produced, including non-default
// ports. In IP mode it consumes the prepared targets directly. In either case
// every probed URL is re-checked against the allowlist, because httpx follows
// redirects and a redirect can leave the authorized scope.
func HTTP(ctx context.Context, e *Env) error {
	livePath := e.Paths.HTTPHosts()
	jsonlPath := e.Paths.ProbeFile()

	// The probe input depends on the mode, and the difference is load-bearing.
	//
	// In IP and ASN mode this stage consumes the host:port pairs naabu found
	// open, including non-default ports, and it therefore runs strictly after the
	// port stage. Dropping the port and probing host:80 would miss every service
	// that is not on the default port.
	//
	// In domain mode the port and HTTP stages run concurrently, so this stage
	// must read the resolved host list instead. Reading the port output here
	// would make a declared-concurrent pair depend on its peer's result.
	input := e.Paths.Resolved()
	explicit := false

	if e.Opts.IPMode {
		if pairs, ok := util.ReadLines(e.Paths.OpenPorts()); ok && len(pairs) > 0 {
			input = e.Paths.HTTPDir + "/probe_targets.txt"
			explicit = true

			// Each pair becomes an explicit URL, so httpx probes that port
			// rather than guessing one. An IPv6 host needs the bracket form.
			var urls []string
			for _, line := range pairs {
				host, port := util.HostPortSplit(line)
				if host == "" || port == "" {
					continue
				}
				if !e.Gate.Scope().Gate(host, port) {
					continue
				}
				if util.IsIPv6(host) {
					urls = append(urls, "http://["+host+"]:"+port)
				} else {
					urls = append(urls, "http://"+host+":"+port)
				}
			}
			if err := util.WriteLines(input, urls); err != nil {
				return err
			}
		}
	}

	lines, ok := util.ReadLines(input)
	if !ok || len(lines) == 0 {
		logging.Warn("no hosts to probe")
		e.Run.SetNote("http", "no probe input")
		return writeHTTPOutputs(livePath, jsonlPath, nil, nil)
	}
	e.Run.SetInputs(len(lines))

	if !e.Tools.Available("httpx") {
		logging.Warn("httpx is not installed; HTTP probing skipped")
		e.Run.SetNote("http", "httpx missing")
		if err := writeHTTPOutputs(livePath, jsonlPath, nil, nil); err != nil {
			return err
		}
		return fmt.Errorf("httpx is not installed")
	}

	// The gate is applied to the input before the probe, so httpx never sees an
	// unauthorized target at all.
	gated := filepath.Join(e.Paths.HTTPDir, "targets.scoped.txt")
	var targets []string
	for _, line := range lines {
		host, port := util.HostPortSplit(line)
		if host == "" {
			continue
		}
		if explicit {
			// The line is already an explicit URL; the gate has seen the host
			// and port separately above.
			targets = append(targets, line)
			continue
		}
		if e.Gate.Scope().Gate(host, port) {
			targets = append(targets, line)
		}
	}
	if err := util.WriteLines(gated, targets); err != nil {
		return err
	}
	if len(targets) == 0 {
		logging.Warn("no probe target survived the scope filter")
		e.Run.SetNote("http", "all probe targets out of scope")
		return writeHTTPOutputs(livePath, jsonlPath, nil, nil)
	}

	args := []string{
		"-silent",
		"-no-color",
		"-l", gated,
		"-threads", strconv.Itoa(e.Opts.Threads),
		"-rate-limit", strconv.Itoa(e.Opts.RateLimit),
		"-timeout", strconv.Itoa(e.Opts.Timeout),
		"-json",
		"-status-code",
		"-title",
		"-tech-detect",
	}
	if e.Opts.Verbose {
		args = append(args,
			"-web-server", "-content-length", "-location",
			"-content-type", "-response-time")
	}
	if explicit {
		// Targets are explicit URLs, so the scheme and port must be preserved
		// rather than inferred from a hostname.
		args = append(args, "-ir")
	}

	logging.Info("httpx probing %d target(s)", len(targets))

	res, runErr := e.Tools.Run(ctx, "httpx", args...)
	if runErr != nil {
		logging.Warn("httpx: %v", runErr)
		e.Run.SetNote("http", "httpx failed")
	}

	records, parseFailed := parseProbeRecords(res.Stdout)
	if len(records) == 0 {
		logging.Warn("httpx returned no records")
		e.Run.SetNote("http", "httpx produced no records")
		return writeHTTPOutputs(livePath, jsonlPath, nil, splitLines(res.Stdout))
	}

	// Re-check every probed URL. httpx may have followed a redirect to another
	// host, so the URL it reports is not necessarily the URL that was probed.
	var live []string
	removed := 0
	for _, r := range records {
		if r.URL == "" {
			continue
		}
		if e.Gate.Scope().URLAllowed(r.URL) {
			live = append(live, r.URL)
			continue
		}
		removed++
		logging.Debug("http: dropped out-of-scope probe result: %s", r.URL)
	}
	if removed > 0 {
		logging.Warn("scope removed %d probed URL(s) from the results", removed)
	}
	sort.Strings(live)

	if err := writeHTTPOutputs(livePath, jsonlPath, live, splitLines(res.Stdout)); err != nil {
		return err
	}
	e.Run.RecordOutputs("http", livePath, jsonlPath)

	if len(live) == 0 {
		e.Run.SetNote("http", "no in-scope live hosts")
		return fmt.Errorf("httpx probed %d target(s) and none were in scope", len(targets))
	}

	logging.Ok("http: %d live host(s)%s", len(live), parseFailedNote(parseFailed))
	return nil
}

// parseFailedNote explains a partial parse rather than dropping records quietly.
func parseFailedNote(failed int) string {
	if failed == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d record(s) could not be parsed)", failed)
}

// writeHTTPOutputs writes the http-stage artifacts, always creating each one.
func writeHTTPOutputs(livePath, jsonlPath string, urls, rawLines []string) error {
	if err := util.WriteLines(livePath, urls); err != nil {
		return err
	}
	return util.WriteLines(jsonlPath, rawLines)
}

// probeRecord is one httpx JSON record.
//
// Only the fields the later stages read are decoded. httpx emits far more, and
// decoding all of it would mean this struct drifting as the tool changes.
type probeRecord struct {
	URL        string   `json:"url"`
	Input      string   `json:"input"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	WebServer  string   `json:"webserver"`
	Tech       []string `json:"tech"`
	Host       string   `json:"host"`
	Port       string   `json:"port"`
}

// parseProbeRecords decodes httpx JSONL, reporting how many lines failed.
//
// A malformed line is counted rather than discarded, because "no records" and
// "records we could not read" are different situations and only one of them is
// a clean result.
func parseProbeRecords(stdout string) (records []probeRecord, failed int) {
	for _, line := range splitLines(stdout) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			// httpx writes non-JSON progress lines to stdout even with -silent
			// in some versions. They are not records.
			continue
		}
		var r probeRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			failed++
			continue
		}
		records = append(records, r)
	}
	return records, failed
}

// Scan runs template-based vulnerability scanning against the live hosts.
//
// This is the last gate before active scanning. nuclei follows redirects and its
// templates can make further requests of their own, so the input list is
// scope-checked immediately before it runs.
func Scan(ctx context.Context, e *Env) error {
	findingsPath := e.Paths.Findings()

	live, _ := util.ReadLines(e.Paths.HTTPHosts())
	if len(live) == 0 {
		logging.Warn("no live hosts to scan")
		e.Run.SetNote("scan", "no live hosts")
		return util.WriteLines(findingsPath, nil)
	}
	e.Run.SetInputs(len(live))

	if !e.Tools.Available("nuclei") {
		logging.Warn("nuclei is not installed; vulnerability scan skipped")
		e.Run.SetNote("scan", "nuclei missing")
		if err := util.WriteLines(findingsPath, nil); err != nil {
			return err
		}
		return fmt.Errorf("nuclei is not installed")
	}

	gated := filepath.Join(e.Paths.ScanDir, "targets.scoped.txt")
	var targets []string
	for _, u := range live {
		if e.Gate.Scope().URLAllowed(u) {
			targets = append(targets, u)
		}
	}
	if err := util.WriteLines(gated, targets); err != nil {
		return err
	}
	if len(targets) == 0 {
		logging.Warn("no live URL survived the scope filter; nuclei not run")
		e.Run.SetNote("scan", "all live urls out of scope")
		return util.WriteLines(findingsPath, nil)
	}

	args := []string{
		"-silent",
		"-l", gated,
		"-severity", e.Opts.NucleiSeverity,
		"-c", strconv.Itoa(e.Opts.Threads),
		"-rl", strconv.Itoa(e.Opts.NucleiRate),
		"-no-color",
	}
	if e.Opts.NucleiTags != "" {
		args = append(args, "-tags", e.Opts.NucleiTags)
	}
	if e.Opts.NucleiNoInteract {
		// Templates that authenticate or submit data make state changes on a
		// live system. They stay off unless the profile asked for them.
		args = append(args, "-ni")
	}
	if e.Opts.NewOnly {
		args = append(args, "-new-template")
	}

	logging.Info("nuclei scanning %d target(s) at severity %s",
		len(targets), e.Opts.NucleiSeverity)

	res, runErr := e.Tools.Run(ctx, "nuclei", args...)
	if runErr != nil {
		logging.Warn("nuclei: %v", runErr)
		e.Run.SetNote("scan", "nuclei failed")
	}

	findings := splitLines(res.Stdout)

	// Findings are reported text, and a finding naming an out-of-scope host
	// would put an unauthorized asset into the report.
	var kept []string
	for _, f := range findings {
		if host := findingHost(f); host == "" || e.Gate.Scope().Gate(host, "") {
			kept = append(kept, f)
		}
	}

	if err := util.WriteLines(findingsPath, kept); err != nil {
		return err
	}
	e.Run.RecordOutputs("scan", findingsPath)

	if len(kept) == 0 {
		logging.Warn("no findings")
		e.Run.SetNote("scan", "zero findings")
		// Zero findings is the desired outcome, not a failure.
		return nil
	}

	logging.Ok("scan: %d finding(s)", len(kept))
	if strings.Contains(strings.ToLower(strings.Join(kept, "\n")), "takeover") {
		logging.Warn("a takeover finding was reported; verify it manually before acting")
	}
	return nil
}

// findingHost extracts the host from a nuclei finding line.
//
// nuclei emits "host:port [status] [severity] template-id - description". The
// host is parsed structurally because a split on the colon would corrupt IPv6.
func findingHost(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	host, _ := util.HostPortSplit(fields[0])
	return host
}
