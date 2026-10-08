package stage

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestPortsRechecksDiscoveredPairs is the property that stops the pipeline
// leaving authorized scope.
//
// A CIDR target yields addresses the allowlist never authorized. Trusting the
// scanner's output here means a later stage contacts them.
func TestPortsRechecksDiscoveredPairs(t *testing.T) {
	h := newHarness(t, "example.com\n192.0.2.0/29\n", "")
	h.seed(h.paths.Resolved(), "example.com\n192.0.2.5\n")

	// naabu reports one authorized and one unauthorized address.
	h.fx.on("naabu", []string{
		"-silent", "-l", h.paths.Resolved(),
		"-c", "25", "-rate", "1000", "-s", "c", "-Pn", "-exclude-cdn",
		"-p", "80,443,8443",
	}, "example.com:443\n192.0.2.5:80\n198.51.100.9:443\n")

	if err := h.runStage("ports", Ports); err != nil {
		t.Fatalf("Ports: %v", err)
	}

	got := h.read(h.paths.OpenPorts())
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "198.51.100.9") {
		t.Errorf("ports = %q; an unauthorized address survived the gate", got)
	}
	for _, want := range []string{"example.com:443", "192.0.2.5:80"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ports = %q, want it to contain %s", got, want)
		}
	}
}

// TestPortsPreservesIPv6 pins that an IPv6 host:port survives canonicalisation.
//
// A split on the first colon turns "[::1]:443" into "[" with an empty port. If
// that happens here the HTTP stage silently probes nothing.
func TestPortsPreservesIPv6(t *testing.T) {
	h := newHarness(t, "example.com\n2001:db8::/32\n", "")
	h.seed(h.paths.Resolved(), "example.com\n")

	h.fx.on("naabu", []string{
		"-silent", "-l", h.paths.Resolved(),
		"-c", "25", "-rate", "1000", "-s", "c", "-Pn", "-exclude-cdn",
		"-p", "80,443,8443",
	}, "[2001:db8::1]:443\n2001:db8::2:443\n2001:db8::1\n")

	if err := h.runStage("ports", Ports); err != nil {
		t.Fatalf("Ports: %v", err)
	}

	got := strings.Join(h.read(h.paths.OpenPorts()), " ")
	if !strings.Contains(got, "[2001:db8::1]:443") {
		t.Errorf("ports = %q, want the bracketed IPv6 pair preserved", got)
	}

	// A bare "2001:db8::2:443" is a valid IPv6 address, not a host and port.
	// It is ambiguous, and guessing wrong would dial the wrong port, so it is
	// dropped rather than reinterpreted.
	if strings.Contains(got, "[2001:db8::2]") {
		t.Errorf("ports = %q; an ambiguous bare IPv6 was reinterpreted as a host:port", got)
	}

	// A host with no port cannot be scanned.
	for _, pair := range h.read(h.paths.OpenPorts()) {
		if pair == "[2001:db8::1]" || pair == "2001:db8::1" {
			t.Errorf("ports kept %q, which has no port", pair)
		}
	}
}

// TestPortsFailsWhenTheScannerIsMissing pins the honest failure.
func TestPortsFailsWhenTheScannerIsMissing(t *testing.T) {
	h := newHarness(t, standardAllow, standardDeny)
	h.seed(h.paths.Resolved(), "example.com\n")
	h.fx.without("naabu")

	if err := h.runStage("ports", Ports); err == nil {
		t.Fatal("Ports returned nil with no scanner")
	}
	h.mustExist(h.paths.OpenPorts(), "the stage ran and scanned nothing")
}

// TestPortsPassesFlagsAsDiscreteArguments pins that the port specification
// reaches the scanner as one argument.
// A comma-separated list is a single argument. Splitting it across two is the
// difference between scanning the listed ports and scanning a nonsense one.
func TestPortsPassesFlagsAsDiscreteArguments(t *testing.T) {
	h := newHarness(t, standardAllow, standardDeny)
	h.seed(h.paths.Resolved(), "example.com\n")

	h.fx.on("naabu", []string{
		"-silent", "-l", h.paths.Resolved(),
		"-c", "25", "-rate", "1000", "-s", "c", "-Pn", "-exclude-cdn",
		"-p", "80,443,8443",
	}, "example.com:443\n")

	if err := h.runStage("ports", Ports); err != nil {
		t.Fatalf("Ports: %v", err)
	}

	// The fixture only responds to this exact argv, so a mismatch would have
	// produced no output above. The assertion below checks the property
	// directly: the port list is one argument, not two.
	for _, call := range h.fx.calls {
		if call.Name != "naabu" {
			continue
		}
		for i, a := range call.Args {
			if a == "-p" {
				if i+1 >= len(call.Args) {
					t.Fatal("-p has no value")
				}
				if call.Args[i+1] != "80,443,8443" {
					t.Errorf("-p value = %q, want the whole list as one argument", call.Args[i+1])
				}
				// The next argument must be a flag, not a bare port.
				if i+2 < len(call.Args) && !strings.HasPrefix(call.Args[i+2], "-") {
					t.Errorf("the port list was split into %q and %q", call.Args[i+1], call.Args[i+2])
				}
			}
		}
	}
}

// TestHTTPGatesBeforeProbing pins that httpx never receives an unauthorized
// target.
func TestHTTPGatesBeforeProbing(t *testing.T) {
	h := newHarness(t, "example.com\n192.0.2.0/24\n", "admin.example.com\n")
	// In domain mode the probe input is the resolved host list, because the port
	// and HTTP stages run concurrently and this one must not wait on the other.
	h.seed(h.paths.Resolved(), "example.com\nadmin.example.com\n198.51.100.5\n")

	gated := filepath.Join(h.paths.HTTPDir, "targets.scoped.txt")
	h.fx.on("httpx", []string{
		"-silent", "-no-color", "-l", gated, "-threads", "10",
		"-rate-limit", "150", "-timeout", "10",
		"-json", "-status-code", "-title", "-tech-detect",
	}, `{"url":"https://example.com","input":"example.com","status_code":200}`+"\n")

	if err := h.runStage("http", HTTP); err != nil {
		t.Fatalf("HTTP: %v", err)
	}

	targets := h.read(gated)
	for _, bad := range []string{"admin.example.com", "198.51.100.5"} {
		for _, got := range targets {
			if got == bad {
				t.Errorf("%s was handed to httpx", bad)
			}
		}
	}

	live := h.read(h.paths.HTTPHosts())
	if len(live) != 1 || live[0] != "https://example.com" {
		t.Errorf("live = %q, want [https://example.com]", live)
	}
}

// TestHTTPDropsOutOfScopeRedirectResults pins the redirect consequence.
//
// httpx follows redirects, so the URL it reports is not necessarily the URL that
// was probed. A redirect to another host would otherwise put that host into the
// live list without ever being gated.
func TestHTTPDropsOutOfScopeRedirectResults(t *testing.T) {
	h := newHarness(t, "example.com\n", "")
	h.seed(h.paths.Resolved(), "example.com\n")

	gated := filepath.Join(h.paths.HTTPDir, "targets.scoped.txt")
	h.fx.on("httpx", []string{
		"-silent", "-no-color", "-l", gated, "-threads", "10",
		"-rate-limit", "150", "-timeout", "10",
		"-json", "-status-code", "-title", "-tech-detect",
	}, strings.Join([]string{
		`{"url":"https://example.com","input":"example.com","status_code":200}`,
		`{"url":"https://attacker.test/landing","input":"example.com","status_code":200}`,
		"",
	}, "\n"))

	err := h.runStage("http", HTTP)
	if err != nil {
		t.Errorf("HTTP = %v; one in-scope host survived, so this should succeed", err)
	}

	live := h.read(h.paths.HTTPHosts())
	for _, u := range live {
		if strings.Contains(u, "attacker.test") {
			t.Errorf("live = %q; a redirect to an out-of-scope host was kept", live)
		}
	}
	if len(live) != 1 || live[0] != "https://example.com" {
		t.Errorf("live = %q, want only the in-scope host", live)
	}
}

// TestHTTPToleratesNonJSONLines pins that httpx's chatter is not mistaken for
// records, and that a genuinely malformed record is counted rather than
// silently dropped.
func TestHTTPToleratesNonJSONLines(t *testing.T) {
	h := newHarness(t, "example.com\n", "")
	h.seed(h.paths.Resolved(), "example.com\n")

	gated := filepath.Join(h.paths.HTTPDir, "targets.scoped.txt")
	h.fx.on("httpx", []string{
		"-silent", "-no-color", "-l", gated, "-threads", "10",
		"-rate-limit", "150", "-timeout", "10",
		"-json", "-status-code", "-title", "-tech-detect",
	}, strings.Join([]string{
		"[INF] using httpx v1.6.0",
		`{"url":"https://example.com","status_code":200}`,
		"{not json at all",
		"",
	}, "\n"))

	if err := h.runStage("http", HTTP); err != nil {
		t.Fatalf("HTTP: %v", err)
	}

	live := h.read(h.paths.HTTPHosts())
	if len(live) != 1 || live[0] != "https://example.com" {
		t.Errorf("live = %q, want the one valid record", live)
	}
}

// TestScanGatesBeforeRunningTemplates pins that the last gate is applied
// immediately before active scanning.
func TestScanGatesBeforeRunningTemplates(t *testing.T) {
	h := newHarness(t, "example.com\n", "admin.example.com\n")
	h.seed(h.paths.HTTPHosts(),
		"https://example.com\nhttps://admin.example.com\nhttps://attacker.test\n")

	gated := filepath.Join(h.paths.ScanDir, "targets.scoped.txt")
	h.fx.on("nuclei", []string{
		"-silent", "-l", gated, "-severity", "low,medium,high,critical",
		"-c", "10", "-rl", "300", "-no-color",
	}, "[https://example.com] [200] [low] tech-detect - nginx\n")

	if err := h.runStage("scan", Scan); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	for _, target := range h.read(gated) {
		if strings.Contains(target, "admin.example.com") || strings.Contains(target, "attacker.test") {
			t.Errorf("%s was handed to nuclei", target)
		}
	}
	findings := strings.Join(h.read(h.paths.Findings()), "\n")
	if !strings.Contains(findings, "example.com") {
		t.Errorf("findings = %q, want the in-scope finding", findings)
	}
}

// TestScanDropsFindingsNamingAnOutOfScopeHost pins that a finding cannot smuggle
// an unauthorized asset into the report.
func TestScanDropsFindingsNamingAnOutOfScopeHost(t *testing.T) {
	h := newHarness(t, "example.com\n", "")
	h.seed(h.paths.HTTPHosts(), "https://example.com\nhttps://attacker.test\n")

	gated := filepath.Join(h.paths.ScanDir, "targets.scoped.txt")
	h.fx.on("nuclei", []string{
		"-silent", "-l", gated, "-severity", "low,medium,high,critical",
		"-c", "10", "-rl", "300", "-no-color",
	}, strings.Join([]string{
		"[https://example.com] [200] [low] x - in scope finding",
		"[https://attacker.test] [200] [critical] y - out of scope finding",
		"[2001:db8::1]:8443] [200] [high] z - ipv6 finding",
		"",
	}, "\n"))

	if err := h.runStage("scan", Scan); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	findings := strings.Join(h.read(h.paths.Findings()), "\n")
	if strings.Contains(findings, "attacker.test") {
		t.Errorf("findings = %q; an out-of-scope finding was kept", findings)
	}
	// The IPv6 finding is dropped too, since the allowlist names example.com
	// only. The point is that the port form is parsed rather than cut.
	if strings.Contains(findings, "2001:db8::1") {
		t.Errorf("findings = %q; an unauthorized IPv6 finding was kept", findings)
	}
}

// TestScanZeroFindingsIsNotAFailure pins that the desired outcome is not
// reported as a problem.
func TestScanZeroFindingsIsNotAFailure(t *testing.T) {
	h := newHarness(t, standardAllow, standardDeny)
	h.seed(h.paths.HTTPHosts(), "https://example.com\n")

	gated := filepath.Join(h.paths.ScanDir, "targets.scoped.txt")
	h.fx.on("nuclei", []string{
		"-silent", "-l", gated, "-severity", "low,medium,high,critical",
		"-c", "10", "-rl", "300", "-no-color",
	}, "")

	if err := h.runStage("scan", Scan); err != nil {
		t.Fatalf("Scan returned %v for zero findings; that is the desired outcome", err)
	}
	h.mustExist(h.paths.Findings(), "the findings file exists even when empty")
}

// TestScanFastProfileDisablesInteractiveTemplates pins the flag that stops
// templates making state changes on a live system.
func TestScanFastProfileDisablesInteractiveTemplates(t *testing.T) {
	h := newHarness(t, standardAllow, standardDeny)
	h.seed(h.paths.HTTPHosts(), "https://example.com\n")
	h.env.Opts.Profile = "fast"
	h.env.Opts.NucleiNoInteract = true
	h.env.Opts.NucleiSeverity = "medium,high,critical"

	gated := filepath.Join(h.paths.ScanDir, "targets.scoped.txt")
	h.fx.on("nuclei", []string{
		"-silent", "-l", gated, "-severity", "medium,high,critical",
		"-c", "10", "-rl", "300", "-no-color", "-ni",
	}, "")

	if err := h.runStage("scan", Scan); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var sawNI bool
	for _, inv := range h.fx.invocations() {
		if strings.Contains(inv, "-ni") {
			sawNI = true
		}
		if strings.Contains(inv, "-severity low,") {
			t.Errorf("fast profile still requested low severity: %q", inv)
		}
	}
	if !sawNI {
		t.Error("the fast profile did not pass -ni; interactive templates stay enabled")
	}
}

// TestContentGatesCrawledResults pins that a crawler cannot widen scope.
//
// A crawler follows links, so it will happily reach a host that was never
// authorized. The result is checked after the fact rather than trusted.
func TestContentGatesCrawledResults(t *testing.T) {
	h := newHarness(t, "example.com\n", "")
	h.seed(h.paths.HTTPHosts(), "https://example.com\n")

	h.fx.on("katana", []string{
		"-silent", "-jsonl", "-d", "2", "-conc", "4", "-timeout", "10",
		"-list", h.paths.HTTPHosts(),
	}, strings.Join([]string{
		`{"request":{"endpoint":"https://example.com/admin"}}`,
		`{"request":{"endpoint":"https://attacker.test/steal"}}`,
		`{"request":{"endpoint":"https://api.example.com/v1"}}`,
		`{malformed`,
		"",
	}, "\n"))

	if err := h.runStage("content", Content); err != nil {
		t.Fatalf("Content: %v", err)
	}

	urls := strings.Join(h.read(h.paths.URLs()), " ")
	if strings.Contains(urls, "attacker.test") {
		t.Errorf("urls = %q; an out-of-scope crawled URL was kept", urls)
	}
	if !strings.Contains(urls, "https://example.com/admin") {
		t.Errorf("urls = %q, want the in-scope endpoint", urls)
	}
	if !strings.Contains(urls, "https://api.example.com/v1") {
		t.Errorf("urls = %q, want the in-scope subdomain", urls)
	}
}
