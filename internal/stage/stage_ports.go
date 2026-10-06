package stage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// Ports scans for open ports, then optionally detects services.
//
// Every discovered host:port is re-checked against the allowlist before any
// downstream stage consumes it. A CIDR target can yield addresses the allowlist
// never authorized, so trusting the scanner's output here would be trusting it
// past the gate.
func Ports(ctx context.Context, e *Env) error {
	out := e.Paths.OpenPorts()

	input := e.Paths.Resolved()
	// In IP mode the port scanner consumes the prepared targets directly,
	// including non-default ports, rather than a resolved host list.
	if e.Opts.IPMode {
		if targets, ok := util.ReadLines(e.Paths.TargetsFile()); ok && len(targets) > 0 {
			input = e.Paths.TargetsFile()
		}
	}

	hosts, _ := util.ReadLines(input)
	if len(hosts) == 0 {
		logging.Warn("no hosts to scan for open ports")
		e.Run.SetNote("ports", "no hosts to scan")
		return writePortsOutputs(out, nil)
	}
	e.Run.SetInputs(len(hosts))

	if !e.Tools.Available("naabu") {
		logging.Warn("naabu is not installed; port scan skipped")
		e.Run.SetNote("ports", "naabu missing")
		if err := writePortsOutputs(out, nil); err != nil {
			return err
		}
		return fmt.Errorf("naabu is not installed")
	}

	// Arguments are a slice, so the port list reaches the scanner as one argument
	// rather than two.
	args := []string{
		"-silent",
		"-l", input,
		"-c", strconv.Itoa(e.Opts.PortConc),
		"-rate", strconv.Itoa(e.Opts.PortRate),
		"-s", "c",
		"-Pn",
		"-exclude-cdn",
	}

	desc := "top " + strconv.Itoa(e.Opts.PortTop) + " ports"
	if e.Opts.PortSpec != "" {
		args = append(args, "-p", e.Opts.PortSpec)
		desc = "ports " + e.Opts.PortSpec
	} else {
		args = append(args, "-top-ports", strconv.Itoa(e.Opts.PortTop))
	}

	logging.Info("naabu scanning %d target(s), %s", len(hosts), desc)

	res, runErr := e.Tools.Run(ctx, "naabu", args...)
	if runErr != nil {
		logging.Error("naabu: %v", runErr)
		e.Run.SetNote("ports", "naabu failed")
	}

	discovered := parseHostPorts(splitLines(res.Stdout))

	// Re-check every discovered pair against the allowlist.
	var kept []string
	removed := 0
	for _, hp := range discovered {
		if e.Gate.Scope().Gate(hp.host, hp.port) {
			kept = append(kept, hp.String())
			continue
		}
		removed++
	}
	if removed > 0 {
		logging.Warn("scope removed %d discovered open port(s) from the results", removed)
	}
	sort.Strings(kept)

	if err := writePortsOutputs(out, kept); err != nil {
		return err
	}
	e.Run.RecordOutputs("ports", out)

	if len(kept) == 0 {
		logging.Warn("no open ports found")
		e.Run.SetNote("ports", "zero open ports")
		// Zero open ports is a real result, not a failure.
		return nil
	}
	logging.Ok("ports: %d open host:port pair(s)", len(kept))

	// Enrichment is best effort. A missing optional tool must not turn a
	// successful port scan into a failed stage.
	if err := nmapServiceDetect(ctx, e); err != nil {
		logging.Debug("ports: nmap enrichment: %v", err)
	}
	if err := censysEnrich(ctx, e); err != nil {
		logging.Debug("ports: censys enrichment: %v", err)
	}
	return nil
}

// writePortsOutputs writes the port-stage artifacts, always creating each one.
func writePortsOutputs(portsPath string, pairs []string) error {
	if err := util.WriteLines(portsPath, pairs); err != nil {
		return err
	}
	return nil
}

// hostPort is one host and port, kept structured so IPv6 survives.
type hostPort struct {
	host string
	port string
}

// String renders the canonical host:port form, bracketing an IPv6 literal.
func (h hostPort) String() string { return util.JoinHostPort(h.host, h.port) }

// parseHostPorts splits scanner output into structured pairs.
//
// The host is never cut on the first colon: that turns "::1" into an empty host
// and "[::1]:443" into "[", which is the bug this function exists to prevent.
func parseHostPorts(lines []string) []hostPort {
	var out []hostPort
	seen := make(map[string]struct{}, len(lines))

	for _, line := range lines {
		host, port := util.HostPortSplit(line)
		if host == "" || port == "" {
			// A host with no port cannot be scanned.
			continue
		}
		hp := hostPort{host: host, port: port}
		key := hp.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, hp)
	}
	return out
}

// groupPortsByHost collects the ports open on each host.
//
// Grouping is done on structured values rather than by splitting a line on a
// delimiter, because an IPv6 literal contains colons.
func groupPortsByHost(pairs []hostPort) map[string][]string {
	byHost := make(map[string][]string)
	for _, p := range pairs {
		byHost[p.host] = append(byHost[p.host], p.port)
	}
	return byHost
}

// nmapServiceDetect runs batched nmap -sV over the discovered ports.
//
// This is the slowest thing in the pipeline, so it is capped rather than left to
// consume the whole runtime budget.
func nmapServiceDetect(ctx context.Context, e *Env) error {
	if !e.Opts.Nmap {
		return nil
	}
	if !e.Tools.Available("nmap") {
		logging.Warn("--nmap requested but nmap is not installed")
		e.Run.SetNote("ports", "nmap missing")
		return nil
	}

	lines, _ := util.ReadLines(e.Paths.OpenPorts())
	if len(lines) == 0 {
		return nil
	}

	pairs := parseHostPorts(lines)
	byHost := groupPortsByHost(pairs)

	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	if total := len(hosts); total > e.Opts.NmapHostCap {
		logging.Warn("nmap: scanning only the first %d of %d hosts (raise the cap to override)",
			e.Opts.NmapHostCap, total)
		hosts = hosts[:e.Opts.NmapHostCap]
	}

	out := filepath.Join(e.Paths.PortsDir, "nmap.txt")
	var collected []string
	scanned := 0

	for _, host := range hosts {
		ports := byHost[host]
		if len(ports) == 0 {
			continue
		}

		// Scope is re-checked per host, with the first port, because a pinned
		// host:port rule applies to that port and not necessarily the host.
		if !e.Gate.Scope().Gate(host, ports[0]) {
			continue
		}

		// IPv6 needs the bracket form for nmap.
		target := host
		if util.IsIPv6(host) {
			target = "[" + host + "]"
		}

		res, err := e.Tools.Run(ctx, "nmap",
			"-sV", "-Pn", "-T4", "--top-ports", "1",
			"-p", strings.Join(ports, ","),
			target)
		if err != nil {
			logging.Debug("ports: nmap %s: %v", target, err)
			continue
		}
		collected = append(collected, res.Stdout)
		scanned++
	}

	if err := util.WriteLines(out, splitLines(strings.Join(collected, "\n"))); err != nil {
		return err
	}
	e.Run.RecordOutputs("ports", e.Paths.OpenPorts(), out)

	if scanned == 0 {
		return fmt.Errorf("no hosts were service-detected")
	}
	logging.Ok("nmap: version scan complete for %d host(s)", scanned)
	return nil
}

// censysEnrich performs a passive service lookup.
//
// Rate limited by design: the free tier allows only a handful of requests per
// second, and being explicit about that is better than getting rate limited.
func censysEnrich(ctx context.Context, e *Env) error {
	if !e.Opts.Censys {
		return nil
	}
	if e.Opts.CensysToken == "" {
		logging.Warn("--censys requested but CENSYS_TOKEN is not set")
		e.Run.SetNote("ports", "censys skipped, no token")
		return nil
	}

	// Addresses first, falling back to the resolved host list.
	ips, ok := util.ReadLines(e.Paths.Addresses())
	if !ok || len(ips) == 0 {
		ips, _ = util.ReadLines(e.Paths.Resolved())
	}
	if len(ips) == 0 {
		logging.Warn("censys: no addresses to look up")
		return nil
	}

	out := filepath.Join(e.Paths.PortsDir, "censys.txt")
	var records []string
	lookedUp := 0

	for _, ip := range ips {
		if !e.Gate.Scope().Gate(ip, "") {
			continue
		}
		// IPv6 must be percent-encoded in a path segment.
		enc := url.PathEscape(ip)
		endpoint := "https://api.platform.censys.io/v3/global/asset/host/" + enc

		body, err := gatedGet(ctx, e, endpoint)
		if err != nil {
			logging.Debug("censys: lookup failed for %s: %v", ip, err)
			continue
		}
		records = append(records, parseCensysServices(ip, body)...)
		lookedUp++

		// The free tier is one request per second. Respect it explicitly.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-newTicker().C:
		}
	}

	if err := util.WriteLines(out, records); err != nil {
		return err
	}
	e.Run.RecordOutputs("ports", e.Paths.OpenPorts(), out)

	logging.Ok("censys: %d passive service record(s) from %d lookups", len(records), lookedUp)
	return nil
}

// parseCensysServices renders the service records from a Censys asset response.
func parseCensysServices(ip string, body []byte) []string {
	var doc struct {
		Result struct {
			Resource struct {
				Services []struct {
					Port     int    `json:"port"`
					Proto    string `json:"transport_protocol"`
					Service  string `json:"protocol"`
					Software []struct {
						Product string `json:"product"`
					} `json:"software"`
				} `json:"services"`
			} `json:"resource"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}

	var out []string
	for _, s := range doc.Result.Resource.Services {
		products := make([]string, 0, len(s.Software))
		for _, sw := range s.Software {
			if sw.Product != "" {
				products = append(products, sw.Product)
			}
		}
		out = append(out, fmt.Sprintf("%s:%d/%s %s %s",
			ip, s.Port, s.Proto, s.Service, strings.Join(products, ",")))
	}
	return out
}
