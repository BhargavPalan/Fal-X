package stage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// Content discovers endpoints: crawling, historical URLs, and optionally
// directory brute force.
//
// It reads only the live host list the HTTP stage wrote. It runs concurrently
// with the scan stage, so it must not read the port stage's output or anything
// else that is not already on disk.
func Content(ctx context.Context, e *Env) error {
	urlsPath := e.Paths.URLs()
	endpointsPath := e.Paths.Endpoints()

	live, _ := util.ReadLines(e.Paths.HTTPHosts())
	if len(live) == 0 {
		// Saying "no live hosts" when the stage that finds them never ran is
		// worse than saying nothing: it reads as a finding about the target
		// rather than a gap in the toolchain.
		if e.Tools.Available("httpx") {
			logging.Warn("no live hosts to crawl")
			e.Run.SetNote("content", "no live hosts")
		} else {
			e.Run.SetNote("content", "httpx not installed, nothing to crawl")
		}
		return writeContentOutputs(urlsPath, endpointsPath, nil, nil)
	}
	e.Run.SetInputs(len(live))

	var endpoints []string
	var allURLs []string
	var notes []string

	// Crawling.
	if e.Tools.Available("katana") {
		args := []string{
			"-silent",
			"-jsonl",
			"-d", strconv.Itoa(e.Opts.KatanaDepth),
			"-conc", strconv.Itoa(e.Opts.Jobs),
			"-timeout", strconv.Itoa(e.Opts.Timeout),
		}
		if e.Opts.FetchJS {
			args = append(args, "-js-crawl")
		}
		args = append(args, "-list", e.Paths.HTTPHosts())

		res, err := e.Tools.Run(ctx, "katana", args...)
		if err != nil {
			logging.Debug("content: katana: %v", err)
			notes = append(notes, "katana failed")
		} else {
			for _, u := range parseKatanaJSONL(res.Stdout) {
				if e.Gate.Scope().URLAllowed(u) {
					allURLs = append(allURLs, u)
				} else {
					logging.Debug("content: dropped out-of-scope crawled URL: %s", u)
				}
			}
		}
	} else {
		notes = append(notes, "katana not installed")
		logging.Debug("content: katana not installed, crawling skipped")
	}

	// Historical URLs. gau reaches third-party archives, so its results are
	// scope-checked like everything else before use.
	if e.Tools.Available("gau") {
		var historical []string
		for _, host := range live {
			if !e.Gate.Scope().URLAllowed(host) {
				continue
			}
			res, err := e.Tools.Run(ctx, "gau", "--subs", "--providers", "wayback,commoncrawl,otx", host)
			if err != nil {
				logging.Debug("content: gau %s: %v", host, err)
				continue
			}
			historical = append(historical, res.Stdout)
		}
		joined := strings.Join(historical, "\n")
		for _, u := range splitLines(joined) {
			if e.Gate.Scope().URLAllowed(u) {
				allURLs = append(allURLs, u)
			}
		}
	} else {
		notes = append(notes, "gau not installed")
	}

	// Directory brute force, which is opt-in.
	if e.Opts.Dirs {
		if !e.Tools.Available("ffuf") {
			logging.Warn("--dirs requested but ffuf is not installed")
			notes = append(notes, "ffuf not installed")
		} else if _, ok := util.ReadLines(e.Opts.DirWordlist); !ok {
			logging.Warn("--dirs requested but %s is missing", e.Opts.DirWordlist)
			notes = append(notes, "dir wordlist missing")
		} else {
			found, err := dirBrute(ctx, e, live)
			if err != nil {
				logging.Debug("content: ffuf: %v", err)
				notes = append(notes, "ffuf failed")
			}
			endpoints = append(endpoints, found...)
		}
	}

	// Normalise and deduplicate.
	allURLs = dedupeSorted(allURLs)
	endpoints = dedupeSorted(append(endpoints, allURLs...))

	if err := writeContentOutputs(urlsPath, endpointsPath, allURLs, endpoints); err != nil {
		return err
	}
	e.Run.RecordOutputs("content", urlsPath, endpointsPath)

	if len(notes) > 0 {
		e.Run.SetNote("content", strings.Join(notes, ", "))
	}
	logging.Ok("content: %d URL(s), %d endpoint(s)", len(allURLs), len(endpoints))
	return nil
}

// writeContentOutputs writes the content-stage artifacts, always creating each.
func writeContentOutputs(urlsPath, endpointsPath string, urls, endpoints []string) error {
	if err := util.WriteLines(urlsPath, urls); err != nil {
		return err
	}
	return util.WriteLines(endpointsPath, endpoints)
}

// dirBrute brute-forces directories on the live hosts.
//
// Only status codes that indicate something was found are kept. Recording every
// 404 turns the endpoint list into a record of the wordlist rather than of the
// target.
func dirBrute(ctx context.Context, e *Env, live []string) ([]string, error) {
	const (
		matchStatus = "200,204,301,302,307,401,403,405,500"
		excludeSize = "0"
	)

	var found []string
	for _, host := range live {
		if !e.Gate.Scope().URLAllowed(host) {
			continue
		}
		res, err := e.Tools.Run(ctx, "ffuf",
			"-s",
			"-w", e.Opts.DirWordlist,
			"-u", host+"/FUZZ",
			"-mc", matchStatus,
			"-fs", excludeSize,
			"-t", strconv.Itoa(e.Opts.Jobs),
			"-timeout", strconv.Itoa(e.Opts.Timeout),
		)
		if err != nil {
			return found, err
		}
		for _, line := range splitLines(res.Stdout) {
			// ffuf prints "http://host/path [STATUS] [SIZE] [WORD]..."
			fields := strings.Fields(line)
			if len(fields) == 0 || !strings.HasPrefix(fields[0], "http") {
				continue
			}
			if e.Gate.Scope().URLAllowed(fields[0]) {
				found = append(found, fields[0])
			}
		}
	}
	return found, nil
}

// parseKatanaJSONL extracts the request URL from katana's JSONL output.
//
// A line that does not parse is skipped rather than aborting the stage, because
// one malformed record should not lose every other endpoint found.
func parseKatanaJSONL(stdout string) []string {
	var out []string
	for _, line := range splitLines(stdout) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var rec struct {
			Request struct {
				Endpoint string `json:"endpoint"`
			} `json:"request"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if u := rec.Request.Endpoint; u != "" {
			out = append(out, u)
		}
	}
	return out
}

// collectCRTSh queries certificate transparency logs for a root.
//
// crt.sh rate-limits hard and returns 502 under load, so only the transport
// failure is retried. A 4xx is never retried, because retrying a refusal just
// wastes the budget.
func collectCRTSh(ctx context.Context, e *Env, roots []string) ([]string, error) {
	const attempts = 3

	var out []string
	var lastErr error

	for _, d := range roots {
		if !e.Gate.Scope().Gate(d, "") {
			continue
		}

		endpoint := "https://crt.sh/?output=json&q=%25." + d

		var body []byte
		for attempt := 1; attempt <= attempts; attempt++ {
			resp, err := e.Gate.GetContext(ctx, endpoint)
			if err != nil {
				lastErr = err
				if ctx.Err() != nil {
					return out, ctx.Err()
				}
				continue
			}
			if resp.StatusCode >= 500 {
				lastErr = fmt.Errorf("crt.sh returned %d", resp.StatusCode)
				continue
			}
			if resp.StatusCode >= 400 {
				// A 4xx is a refusal, not a transient failure.
				lastErr = fmt.Errorf("crt.sh refused with %d", resp.StatusCode)
				break
			}
			body = resp.Body
			lastErr = nil
			break
		}
		if body == nil {
			logging.Debug("subs: crt.sh lookup failed for %s: %v", d, lastErr)
			continue
		}

		out = append(out, parseCRTShNames(body)...)
	}

	return out, nil
}

// parseCRTShNames extracts the names from a crt.sh response.
//
// A single name_value field carries several comma-separated names, including
// wildcard entries, so it is split before the wildcard prefix is stripped.
func parseCRTShNames(body []byte) []string {
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	var out []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, ",") {
			n := strings.TrimSpace(strings.ToLower(name))
			n = strings.TrimPrefix(n, "*.")
			if util.ValidDomain(n) {
				out = append(out, n)
			}
		}
	}
	return out
}

// safeCollect runs a collector, converting a panic into an error.
//
// A collector is third-party output. One that crashes must cost its own results
// and nothing else.
func safeCollect(ctx context.Context,
	fn func(context.Context, *Env, []string) ([]string, error),
	e *Env, roots []string,
) (lines []string, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			lines = nil
			err = fmt.Errorf("collector panicked: %v", rec)
		}
	}()
	return fn(ctx, e, roots)
}

// dedupeSorted removes duplicates and returns the result sorted.
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// unusedPath keeps the filepath import honest for the helpers above.
