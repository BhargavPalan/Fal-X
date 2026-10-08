package stage

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRootsFiltersThroughScope pins that the roots stage keeps only names the
// allowlist authorizes.
func TestRootsFiltersThroughScope(t *testing.T) {
	h := newHarness(t, standardAllow, standardDeny)

	err := h.runStage("roots", Roots)
	if err != nil {
		t.Fatalf("Roots: %v", err)
	}

	got := h.read(h.paths.Roots())
	if len(got) != 1 || got[0] != "example.com" {
		t.Errorf("roots = %q, want [example.com]", got)
	}
	h.mustExist(h.paths.Roots(), "the roots stage ran")
}

// TestRootsRejectsUntrustedOutput pins that free-form tool output is validated
// before use.
//
// amass returns prose and URLs alongside domains. Passing those downstream would
// fail a later stage confusingly, or worse, reach a scanner as a target.
func TestRootsRejectsUntrustedOutput(t *testing.T) {
	h := newHarness(t, "example.com\n", "")

	// amass is only reached when an org name is set.
	h.env.Opts.Org = "Example Ltd"
	h.env.Opts.Amass = true
	h.fx.on("amass", []string{"intel", "-whois", "-d", "example.com"}, strings.Join([]string{
		"example.com",
		"  api.example.com  ",
		"EXAMPLE.COM",
		"example.com.",
		// Untrusted noise that must not survive.
		"whois record for EXAMPLE.COM",
		"https://example.com/path",
		"not a domain at all",
		"attacker.test",
		"127.0.0.1",
	}, "\n"))

	if err := h.runStage("roots", Roots); err != nil {
		t.Fatalf("Roots: %v", err)
	}

	got := h.read(h.paths.Roots())
	want := []string{"api.example.com", "example.com"}
	if len(got) != len(want) {
		t.Fatalf("roots = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("roots[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRootsSkipsInIPMode pins that a run with no domain does not try to expand
// one.
func TestRootsSkipsInIPMode(t *testing.T) {
	h := newHarness(t, standardAllow, standardDeny)
	h.env.Opts.IPMode = true

	if err := h.runStage("roots", Roots); err != nil {
		t.Fatalf("Roots: %v", err)
	}
	if h.fx.calledTool("subfinder") || h.fx.calledTool("amass") {
		t.Error("a collector ran in IP mode")
	}
}

// TestSubsMergesCollectorsAndGatesScope is the core of the subdomain stage.
//
// Two properties at once: collectors are merged into one result, and a
// discovery outside the allowlist is recorded separately rather than mixed in
// or thrown away. An out-of-scope subdomain under an in-scope root is a real
// finding about the estate.
func TestSubsMergesCollectorsAndGatesScope(t *testing.T) {
	h := newHarness(t, standardAllow, standardDeny)
	h.seed(h.paths.Roots(), "example.com\n")

	h.fx.on("subfinder", []string{
		"-silent", "-all", "-timeout", "20", "-t", "10", "-dL", h.paths.Roots(),
	}, "api.example.com\nwww.example.com\nadmin.example.com\nexample.com.attacker.test\n")

	if err := h.runStage("subs", Subs); err != nil {
		t.Fatalf("Subs: %v", err)
	}

	inScope := h.read(h.paths.Subs())
	// admin.example.com is denied by the denylist; the attacker suffix is not
	// under the root at all so it never reaches the scope gate.
	want := []string{"api.example.com", "www.example.com"}
	if len(inScope) != len(want) {
		t.Fatalf("subs = %q, want %q", inScope, want)
	}
	for i := range want {
		if inScope[i] != want[i] {
			t.Errorf("subs[%d] = %q, want %q", i, inScope[i], want[i])
		}
	}

	rejected := h.read(h.paths.Rejected())
	if len(rejected) != 1 || rejected[0] != "admin.example.com" {
		t.Errorf("out-of-scope list = %q, want [admin.example.com]", rejected)
	}

	h.mustExist(h.paths.Rejected(), "the rejected list is always written")
}

// TestSubsRestrictsToRoots pins the label-aware root check.
//
// A substring test would let example.com.attacker.test through while scanning
// example.com. That is the single most important property in this file.
func TestSubsRestrictsToRoots(t *testing.T) {
	h := newHarness(t, "example.com\n", "")
	h.seed(h.paths.Roots(), "example.com\n")

	// A collector that returns names only superficially under the root.
	h.fx.on("subfinder", []string{
		"-silent", "-all", "-timeout", "20", "-t", "10", "-dL", h.paths.Roots(),
	}, strings.Join([]string{
		"example.com",               // the root itself
		"api.example.com",           // a true subdomain
		"example.com.attacker.test", // suffix spoof
		"notexample.com",            // prefix extension
		"evil-example.com",          // hyphen prefix
		"example-com.attacker.test",
	}, "\n"))

	if err := h.runStage("subs", Subs); err != nil {
		t.Fatalf("Subs: %v", err)
	}

	got := h.read(h.paths.Subs())
	want := []string{"api.example.com", "example.com"}
	if len(got) != len(want) {
		t.Fatalf("subs = %q, want exactly %q; a spoofed name got through", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("subs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestSubsSurvivesAFailingCollector pins that one broken collector costs only
// its own results.
//
// Every collector still writes a file, so the merge is total. A collector that
// was never run and one that found nothing are then distinguishable by presence.
func TestSubsSurvivesAFailingCollector(t *testing.T) {
	h := newHarness(t, "example.com\n", "")
	h.seed(h.paths.Roots(), "example.com\n")

	h.fx.on("subfinder", []string{
		"-silent", "-all", "-timeout", "20", "-t", "10", "-dL", h.paths.Roots(),
	}, "api.example.com\n")
	// No response recorded for the crt.sh collectors, so they fail.
	h.fx.on("gau", []string{"--subs", "--providers", "wayback,commoncrawl,otx", "https://example.com"}, "")

	if err := h.runStage("subs", Subs); err != nil {
		t.Fatalf("Subs: %v", err)
	}

	got := h.read(h.paths.Subs())
	if len(got) != 1 || got[0] != "api.example.com" {
		t.Errorf("subs = %q, want the surviving collector's result", got)
	}

	// A collector that failed still left its file, so absence means "never ran".
	h.mustExist(h.paths.SubsDir+"/_col_subfinder.txt", "subfinder wrote results")
}

// TestSubsWithoutRootsIsNotAFailure pins that an empty input is a clean result,
// not a crash.
func TestSubsWithoutRootsIsNotAFailure(t *testing.T) {
	h := newHarness(t, standardAllow, standardDeny)
	if err := h.runStage("subs", Subs); err != nil {
		t.Fatalf("Subs with no roots = %v, want nil", err)
	}
	h.mustExist(h.paths.Subs(), "the output is always created")
	if h.fx.calledTool("subfinder") {
		t.Error("a collector ran with no roots")
	}
}

// TestResolveFailsWhenTheResolverIsMissing pins the honest-failure choice.
//
// Falling back to treating every candidate as a live host would feed unverified
// names into the port scanner and produce results that look real but are not.
func TestResolveFailsWhenTheResolverIsMissing(t *testing.T) {
	h := newHarness(t, standardAllow, standardDeny)
	h.seed(h.paths.Roots(), "example.com\n")
	h.seed(h.paths.Subs(), "api.example.com\n")
	h.fx.without("dnsx")

	err := h.runStage("resolve", Resolve)
	if err == nil {
		t.Fatal("Resolve returned nil with no resolver; unverified hosts would have been reported as live")
	}

	// All three outputs exist and are empty, which is different from absent.
	h.mustExist(h.paths.Resolved(), "resolve ran and verified nothing")
	h.mustExist(h.paths.Addresses(), "resolve ran and found no addresses")
	h.mustExist(h.paths.Records(), "resolve ran and dumped no records")

	if len(h.read(h.paths.Resolved())) != 0 {
		t.Error("an unverified name was written to the resolved list")
	}
}

// TestResolveGatesCandidatesBeforeResolving pins that the resolver never sees an
// unauthorized name.
func TestResolveGatesCandidatesBeforeResolving(t *testing.T) {
	h := newHarness(t, "example.com\n", "admin.example.com\n")
	h.seed(h.paths.Roots(), "example.com\n")
	// An out-of-scope candidate alongside in-scope ones.
	h.seed(h.paths.Subs(), "api.example.com\nadmin.example.com\nattacker.test\n")

	gatedPath := filepath.Join(h.paths.ResolveDir, "candidates.scoped.txt")
	h.fx.on("dnsx", []string{"-silent", "-t", "10", "-l", gatedPath}, "api.example.com\nexample.com\n")
	h.fx.on("dnsx", []string{"-silent", "-nc", "-l", h.paths.Resolved(),
		"-a", "-aaaa", "-cname", "-ns", "-mx", "-resp", "-resp-only"},
		"api.example.com [A] 192.0.2.10\nexample.com [A] 192.0.2.11\n")

	if err := h.runStage("resolve", Resolve); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// The gated list handed to dnsx excluded the out-of-scope names.
	gated := h.read(gatedPath)
	for _, bad := range []string{"admin.example.com", "attacker.test"} {
		for _, g := range gated {
			if g == bad {
				t.Errorf("%s was passed to the resolver", bad)
			}
		}
	}

	got := h.read(h.paths.Resolved())
	if len(got) != 2 {
		t.Errorf("resolved = %q, want two hosts", got)
	}
}

// TestResolveExtractsBothAddressFamilies pins that IPv6 is not dropped.
// A dual-stack host contributes one of each, and every downstream consumer needs
// both.
func TestResolveExtractsBothAddressFamilies(t *testing.T) {
	h := newHarness(t, "example.com\n2001:db8::/32\n192.0.2.0/24\n", "")
	h.seed(h.paths.Roots(), "example.com\n")

	h.fx.on("dnsx", []string{"-silent", "-t", "10", "-l", filepath.Join(h.paths.ResolveDir, "candidates.scoped.txt")},
		"example.com\n")
	h.fx.on("dnsx", []string{"-silent", "-nc", "-l", h.paths.Resolved(),
		"-a", "-aaaa", "-cname", "-ns", "-mx", "-resp", "-resp-only"},
		"example.com [A] 192.0.2.10\nexample.com [AAAA] 2001:db8::10\n")

	if err := h.runStage("resolve", Resolve); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	ips := h.read(h.paths.Addresses())
	joined := strings.Join(ips, " ")
	if !strings.Contains(joined, "192.0.2.10") {
		t.Errorf("addresses = %q, want the IPv4 address", ips)
	}
	if !strings.Contains(joined, "2001:db8::10") {
		t.Errorf("addresses = %q, want the IPv6 address; IPv6 is being dropped", ips)
	}
}

// TestResolveGatesExtractedAddresses pins that an address found by DNS is itself
// scope-checked.
//
// A name can resolve outside the allowlist, and a scanner must not follow it
// there just because the name was authorized.
func TestResolveGatesExtractedAddresses(t *testing.T) {
	h := newHarness(t, "example.com\n192.0.2.0/24\n", "")
	h.seed(h.paths.Roots(), "example.com\n")

	h.fx.on("dnsx", []string{"-silent", "-t", "10", "-l", filepath.Join(h.paths.ResolveDir, "candidates.scoped.txt")},
		"example.com\n")
	// The name resolves to an address outside the authorized range.
	h.fx.on("dnsx", []string{"-silent", "-nc", "-l", h.paths.Resolved(),
		"-a", "-aaaa", "-cname", "-ns", "-mx", "-resp", "-resp-only"},
		"example.com [A] 198.51.100.5\n")

	if err := h.runStage("resolve", Resolve); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	ips := h.read(h.paths.Addresses())
	if len(ips) != 0 {
		t.Errorf("addresses = %q, want the out-of-scope address dropped", ips)
	}
}
