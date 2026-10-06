package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parse fails the test on an unexpected parse error.
func parse(t *testing.T, args ...string) *Options {
	t.Helper()
	opts, err := Parse(args...)
	if err != nil {
		t.Fatalf("Parse(%q) = %v, want no error", args, err)
	}
	return opts
}

// mustRefuse requires Precheck to refuse with a specific kind.
func mustRefuse(t *testing.T, kind Refusal, args ...string) *Options {
	t.Helper()
	opts := parse(t, args...)
	if err := opts.Precheck(); err == nil {
		t.Fatalf("Precheck(%q) = nil, want %s", args, kind)
	}
	return opts
}

// scopeWith writes a scope file and returns its path.
func scopeWith(t *testing.T, allow, deny string) string {
	t.Helper()
	dir := t.TempDir()

	allowPath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(allowPath, []byte(allow), 0o600); err != nil {
		t.Fatal(err)
	}
	if denyPath := filepath.Join(dir, "deny.txt"); deny != "" {
		if err := os.WriteFile(denyPath, []byte(deny), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return allowPath
}

// scopeFile is the fixture most tests use.
func scopeFile(t *testing.T) string {
	return scopeWith(t, "example.com\n*.wild.test\n192.0.2.0/24\n", "admin.example.com\n")
}

// asksForConfirmation reports whether Precheck asked to confirm a wide target.
func asksForConfirmation(err error) (*NeedsConfirm, bool) {
	var needs *NeedsConfirm
	if errors.As(err, &needs) {
		return needs, true
	}
	return nil, false
}

// TestExactlyOneTargetIsRequired pins the mutually exclusive target selection.
func TestExactlyOneTargetIsRequired(t *testing.T) {
	sf := scopeFile(t)

	t.Run("none", func(t *testing.T) {
		opts := parse(t, "--scope", sf)
		err := opts.Precheck()
		if err == nil {
			t.Fatal("Precheck accepted a run with no target")
		}
		if got := RefusalKind(err); got != RefuseUsage {
			t.Errorf("refusal kind = %v, want %v", got, RefuseUsage)
		}
	})

	for _, extra := range [][]string{
		{"-d", "example.com", "-ip", "192.0.2.5"},
		{"-d", "example.com", "-l", "h.txt", "-ip", "192.0.2.5", "-asn", "AS12345"},
	} {
		if _, err := Parse(append([]string{"--scope", sf}, extra...)...); err == nil {
			t.Errorf("Parse accepted mutually exclusive targets %q", extra)
		}
	}

	for _, extra := range [][]string{
		{"-d", "example.com"},
		{"-l", "hosts.txt"},
		{"-ip", "192.0.2.5"},
		{"-asn", "AS12345"},
	} {
		opts := parse(t, append(append([]string{"--scope", sf}, extra...), "--dry-run")...)
		if opts.Target() == "" {
			t.Errorf("Target() is empty for %q", extra)
		}
	}
}

// TestNoAcknowledgementFlag pins that there is no blanket authorization flag.
//
// The allowlist is already mandatory and already fails closed, so a flag beside
// it is a second gate saying the same thing. Worse, a flag people learn to type
// reflexively stops being a signal at all. No other tool in this category
// requires one, and neither does this one.
func TestNoAcknowledgementFlag(t *testing.T) {
	for _, name := range []string{"--authorized", "--ack", "--yes-i-do"} {
		if _, err := Parse("-d", "example.com", name); err == nil {
			t.Errorf("Parse accepted %q, which is deliberately not a flag", name)
		}
	}
}

// TestASingleDomainNeedsNoCeremony is the common case and must be unobstructed.
// One domain against a tight allowlist is already an explicit decision.
func TestASingleDomainNeedsNoCeremony(t *testing.T) {
	opts := parse(t, "-d", "example.com", "--scope", scopeFile(t))
	if err := opts.Precheck(); err != nil {
		t.Errorf("Precheck = %v, want nil; a scoped single domain needs no confirmation", err)
	}
}

// TestWideTargetsAskForConfirmation covers the blast-radius confirmation.
//
// An allowlist says what may be touched. It cannot express how far a target
// reaches, so an autonomous system, a large prefix, or a bare wildcard is
// confirmed instead, while an ordinary scoped target is not.
func TestWideTargetsAskForConfirmation(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantAsk bool
	}{
		{
			"large prefix",
			[]string{"-ip", "192.0.2.0/8", "--allow-private",
				"--scope", scopeWith(t, "192.0.2.0/8\n", "")},
			true,
		},
		{
			"small prefix",
			[]string{"-ip", "192.0.2.0/29", "--allow-private",
				"--scope", scopeWith(t, "192.0.2.0/29\n", "")},
			false,
		},
		{
			"bare address",
			[]string{"-ip", "192.0.2.5", "--allow-private",
				"--scope", scopeWith(t, "192.0.2.0/24\n", "")},
			false,
		},
		{
			"single domain",
			[]string{"-d", "example.com", "--scope", scopeFile(t)},
			false,
		},
		{
			"bare wildcard",
			[]string{"-d", "anything.test", "--allow-any",
				"--scope", scopeWith(t, "*\n", "")},
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := parse(t, tc.args...)
			err := opts.Precheck()

			needs, asked := asksForConfirmation(err)
			if asked != tc.wantAsk {
				t.Fatalf("confirmation asked = %v, want %v (err = %v)", asked, tc.wantAsk, err)
			}
			if !asked {
				if err != nil {
					t.Fatalf("Precheck = %v, want nil", err)
				}
				return
			}
			if needs.Prompt == "" {
				t.Error("the confirmation carries no prompt")
			}
			if needs.Reason == "" {
				t.Error("the confirmation carries no reason")
			}

			// Answering it must let the run proceed.
			opts.Yes = true
			if err := opts.Precheck(); err != nil {
				t.Errorf("Precheck after confirmation = %v, want nil", err)
			}
		})
	}
}

// TestASNAlwaysAsks pins that an autonomous system is always confirmed. It
// resolves to netblocks the operator never saw, so no allowlist can describe it.
func TestASNAlwaysAsks(t *testing.T) {
	opts := parse(t, "-asn", "AS12345", "--scope", scopeFile(t))

	if _, asked := asksForConfirmation(opts.Precheck()); !asked {
		t.Fatal("Precheck did not ask to confirm an ASN target")
	}

	opts.Yes = true
	if err := opts.Precheck(); err != nil {
		t.Errorf("Precheck after confirmation = %v, want nil", err)
	}
}

// TestDryRunIsNeverBlocked pins that planning is always possible, because it is
// how an operator finds out what they got wrong.
func TestDryRunIsNeverBlocked(t *testing.T) {
	sf := scopeFile(t)

	if err := parse(t, "-d", "example.com", "--scope", sf, "--dry-run").Precheck(); err != nil {
		t.Errorf("Precheck for a dry run = %v, want nil", err)
	}

	// Even a target that would need confirming, and even with no allowlist.
	for _, args := range [][]string{
		{"-ip", "192.0.2.0/8", "--scope", sf, "--allow-private", "--dry-run"},
		{"-d", "example.com", "--scope", filepath.Join(t.TempDir(), "nope.txt"), "--dry-run"},
	} {
		if err := parse(t, args...).Precheck(); err != nil {
			t.Errorf("Precheck(%q) for a dry run = %v, want nil", args, err)
		}
	}
}

// TestMissingAllowlistFailsClosed pins that an absent, empty or comment-only
// allowlist refuses the run. It must never widen scope to compensate.
func TestMissingAllowlistFailsClosed(t *testing.T) {
	dir := t.TempDir()

	// Naming a file that is not there is an instruction that could not be
	// carried out. Refusing is the honest response, because running without the
	// boundary the operator asked for is the one outcome nobody intended.
	t.Run("absent but requested", func(t *testing.T) {
		mustRefuse(t, RefuseScope, "-d", "example.com",
			"--scope", filepath.Join(dir, "nope.txt"))
	})

	t.Run("empty", func(t *testing.T) {
		p := filepath.Join(dir, "empty.txt")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		mustRefuse(t, RefuseScope, "-d", "example.com", "--scope", p)
	})

	t.Run("comments only", func(t *testing.T) {
		p := filepath.Join(dir, "comments.txt")
		if err := os.WriteFile(p, []byte("# nothing here\n# still nothing\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		mustRefuse(t, RefuseScope, "-d", "example.com", "--scope", p)
	})
}

// With no --scope flag and no default file present, the run is unrestricted.
// This is the default because a bare target should work without ceremony, the
// way it does in nmap or httpx.
func TestNoAllowlistRunsUnrestricted(t *testing.T) {
	t.Setenv("FALX_HOME", t.TempDir())

	opts := parse(t, "-d", "anything.example")
	if err := opts.Precheck(); err != nil {
		t.Fatalf("Precheck = %v, want nil: a missing allowlist is the default", err)
	}
	if opts.Scope().Loaded() {
		t.Error("scope reports loaded; nothing was configured, so nothing should be")
	}
	if !opts.Scope().Gate("anything.example", "") {
		t.Error("Gate denied a target with no allowlist configured")
	}
	if out := opts.Explain("anything.example"); !strings.Contains(out, "ALLOWED") {
		t.Errorf("Explain = %q, want ALLOWED", out)
	}
}

// TestDefaultScopePathIsUsableAfterSetup pins the other half: once the default
// allowlist exists, a run with no --scope flag works. This is the state fal-x install --setup
// --setup leaves behind, so it is the first thing a new user does.
func TestDefaultScopePathIsUsableAfterSetup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("FALX_HOME", home)

	if err := os.MkdirAll(filepath.Join(home, "config"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config", "scope.txt"),
		[]byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := parse(t, "-d", "example.com")
	if err := opts.Precheck(); err != nil {
		t.Errorf("Precheck with a default allowlist in place = %v, want nil", err)
	}
}

// TestWhyDeniedNeedsOnlyAnAllowlist pins the diagnostic path. It makes no
// requests, so it must not ask to be confirmed and must not need anything else.
func TestWhyDeniedUsesTheConfiguredAllowlist(t *testing.T) {
	sf := scopeFile(t)

	opts := parse(t, "--scope", sf, "--why-denied", "example.com")
	if err := opts.Precheck(); err != nil {
		t.Errorf("Precheck for --why-denied = %v, want nil", err)
	}
	if opts.WhyDenied != "example.com" {
		t.Errorf("WhyDenied = %q", opts.WhyDenied)
	}

	// A scope file that was named but cannot be read is still an error. The
	// operator asked for a boundary, so silently running without one would
	// discard the instruction rather than report that it failed.
	opts = parse(t, "--scope", filepath.Join(t.TempDir(), "nope.txt"),
		"--why-denied", "example.com")
	if err := opts.Precheck(); err == nil {
		t.Fatal("Precheck accepted --why-denied with an unreadable allowlist")
	} else if got := RefusalKind(err); got != RefuseScope {
		t.Errorf("refusal kind = %v, want %v", got, RefuseScope)
	}
}

// With no allowlist there is no boundary to explain, but the answer is still
// worth giving: everything is reachable, and --scope is how to change that.
func TestWhyDeniedWithoutAnAllowlist(t *testing.T) {
	t.Setenv("FALX_HOME", t.TempDir())

	opts := parse(t, "-d", "anything.example", "--why-denied", "anything.example")
	if err := opts.Precheck(); err != nil {
		t.Fatalf("Precheck = %v, want nil: a missing allowlist is the default, not a failure", err)
	}
	out := opts.Explain("anything.example")
	if !strings.Contains(out, "ALLOWED") {
		t.Errorf("Explain = %q, want it to report the target as reachable", out)
	}
	if !strings.Contains(out, "--scope") {
		t.Errorf("Explain = %q, want it to say how to restrict a run", out)
	}
}

// TestOutOfScopeTargetIsRefusedBeforeAnyRequest pins that the target itself is
// checked up front rather than left to the per-request gate.
func TestOutOfScopeTargetIsRefusedBeforeAnyRequest(t *testing.T) {
	sf := scopeFile(t)

	mustRefuse(t, RefuseScope, "-d", "attacker.test", "--scope", sf)
	mustRefuse(t, RefuseScope, "-ip", "192.0.4.5", "--scope", sf)

	if err := parse(t, "-d", "example.com", "--scope", sf).Precheck(); err != nil {
		t.Errorf("Precheck for an in-scope target = %v, want nil", err)
	}
}

// TestPrivateRangesNeedOptIn pins that --allow-private is required and that it
// does not widen the allowlist.
func TestPrivateRangesNeedOptIn(t *testing.T) {
	p := scopeWith(t, "10.0.0.0/8\nlab.test\n", "")

	// A private address is refused on an active run, and not on a dry run,
	// because a dry run contacts nothing.
	mustRefuse(t, RefuseScope, "-ip", "10.1.2.3", "--scope", p)
	if err := parse(t, "-ip", "10.1.2.3", "--scope", p, "--dry-run").Precheck(); err != nil {
		t.Errorf("dry run refused a private target: %v", err)
	}

	opts := parse(t, "-ip", "10.1.2.3", "--scope", p, "--allow-private", "--yes")
	if err := opts.Precheck(); err != nil {
		t.Errorf("Precheck with --allow-private = %v, want nil", err)
	}

	// The switch must not bring in an address that was never allowlisted.
	opts = parse(t, "-ip", "192.168.1.1", "--scope", p, "--allow-private", "--yes")
	if err := opts.Precheck(); err == nil {
		t.Error("--allow-private widened the allowlist to cover 192.168.1.1")
	}
}

// TestBareWildcardNeedsAllowAny pins that a scope file containing only "*" is
// refused unless the operator opts in explicitly.
func TestBareWildcardNeedsAllowAny(t *testing.T) {
	p := scopeWith(t, "*\n", "")

	mustRefuse(t, RefuseScope, "-d", "anything.test", "--scope", p)

	opts := parse(t, "-d", "anything.test", "--scope", p, "--allow-any", "--yes")
	if err := opts.Precheck(); err != nil {
		t.Errorf("Precheck with --allow-any = %v, want nil", err)
	}
}

// TestStageSelection pins stage parsing and the unknown-stage refusal.
func TestStageSelection(t *testing.T) {
	base := []string{"-d", "example.com", "--scope", scopeFile(t)}

	t.Run("all stages by default", func(t *testing.T) {
		opts := parse(t, base...)
		for _, s := range AllStages {
			if !opts.StageEnabled(s) {
				t.Errorf("stage %s is off by default", s)
			}
		}
	})

	t.Run("explicit subset", func(t *testing.T) {
		opts := parse(t, append(append([]string{}, base...), "--stages", "subs,resolve,http")...)
		for _, s := range []string{"subs", "resolve", "http"} {
			if !opts.StageEnabled(s) {
				t.Errorf("stage %s should be enabled", s)
			}
		}
		for _, s := range []string{"roots", "ports", "content", "scan"} {
			if opts.StageEnabled(s) {
				t.Errorf("stage %s should be disabled by --stages", s)
			}
		}
	})

	t.Run("whitespace is tolerated", func(t *testing.T) {
		opts := parse(t, append(append([]string{}, base...), "--stages", " subs , resolve , http ")...)
		if !opts.StageEnabled("subs") || !opts.StageEnabled("http") {
			t.Error("whitespace around stage names was not tolerated")
		}
	})

	t.Run("unknown stage is a usage error", func(t *testing.T) {
		_, err := Parse(append(append([]string{}, base...), "--stages", "subs,nope")...)
		if err == nil {
			t.Fatal("Parse accepted an unknown stage")
		}
		if got := RefusalKind(err); got != RefuseUsage {
			t.Errorf("refusal kind = %v, want %v", got, RefuseUsage)
		}
	})

	t.Run("empty list keeps everything", func(t *testing.T) {
		opts := parse(t, append(append([]string{}, base...), "--stages", "")...)
		if !opts.StageEnabled("scan") {
			t.Error("an empty --stages disabled everything")
		}
	})

	t.Run("skip-scan", func(t *testing.T) {
		opts := parse(t, append(append([]string{}, base...), "--skip-scan")...)
		if opts.StageEnabled("scan") {
			t.Error("--skip-scan left the scan stage enabled")
		}
		if !opts.StageEnabled("http") {
			t.Error("--skip-scan disabled more than the scan stage")
		}
	})

	t.Run("skip-scan does not override an explicit list", func(t *testing.T) {
		opts := parse(t, append(append([]string{}, base...),
			"--stages", "http,scan", "--skip-scan")...)
		if !opts.StageEnabled("scan") {
			t.Error("--skip-scan overrode an explicit --stages listing")
		}
	})
}

// TestProfileValidation pins that an unknown profile is rejected rather than
// silently behaving as normal.
func TestProfileValidation(t *testing.T) {
	base := []string{"-d", "example.com", "--scope", scopeFile(t)}

	for _, name := range []string{"fast", "normal", "exhaustive"} {
		if opts := parse(t, append(append([]string{}, base...), "--profile", name)...); opts.Profile != name {
			t.Errorf("Profile = %q, want %q", opts.Profile, name)
		}
	}
	if _, err := Parse(append(append([]string{}, base...), "--profile", "quick")...); err == nil {
		t.Error("Parse accepted an unknown profile")
	}
	if opts := parse(t, append(append([]string{}, base...), "--fast")...); opts.Profile != "fast" {
		t.Errorf("--fast set Profile to %q, want fast", opts.Profile)
	}
}

// TestOptionalStagesAreOffByDefault pins that the expensive stages require an
// explicit request.
func TestOptionalStagesAreOffByDefault(t *testing.T) {
	base := []string{"-d", "example.com", "--scope", scopeFile(t)}

	opts := parse(t, base...)
	if opts.Brute || opts.Dirs || opts.Nmap || opts.Amass || opts.Censys {
		t.Error("an expensive stage was enabled by default")
	}

	opts = parse(t, append(append([]string{}, base...),
		"--brute", "--dirs", "--nmap", "--deep", "--censys")...)
	if !opts.Brute || !opts.Dirs || !opts.Nmap || !opts.Amass || !opts.Censys {
		t.Error("an explicitly requested stage did not take effect")
	}
}

// TestPortSpecValidation pins the port flag grammar.
func TestPortSpecValidation(t *testing.T) {
	base := []string{"-d", "example.com", "--scope", scopeFile(t)}

	for _, spec := range []string{"80", "80,443", "1-1024", "80,443,8000-8100"} {
		if _, err := Parse(append(append([]string{}, base...), "--ports", spec)...); err != nil {
			t.Errorf("Parse rejected a valid port spec %q: %v", spec, err)
		}
	}
	for _, spec := range []string{"", "80,", "a", "80-", "65536", "80-70"} {
		if _, err := Parse(append(append([]string{}, base...), "--ports", spec)...); err == nil {
			t.Errorf("Parse accepted an invalid port spec %q", spec)
		}
	}
}

// TestIPAndASNValidation pins the target-shape checks.
func TestIPAndASNValidation(t *testing.T) {
	base := []string{"--scope", scopeFile(t)}

	for _, v := range []string{"192.0.2.5", "192.0.2.0/24", "2001:db8::1", "2001:db8::/32"} {
		if _, err := Parse(append(append([]string{}, base...), "-ip", v)...); err != nil {
			t.Errorf("Parse rejected a valid target %q: %v", v, err)
		}
	}
	for _, v := range []string{"not-an-ip", "192.0.2.999", "192.0.2.0/33", "1.2.3", ""} {
		if _, err := Parse(append(append([]string{}, base...), "-ip", v)...); err == nil {
			t.Errorf("Parse accepted an invalid target %q", v)
		}
	}

	for _, v := range []string{"AS12345", "as12345", "As12345"} {
		opts, err := Parse(append(append([]string{}, base...), "-asn", v)...)
		if err != nil {
			t.Errorf("Parse rejected %q: %v", v, err)
			continue
		}
		if opts.ASN != "AS12345" {
			t.Errorf("ASN = %q, want AS12345", opts.ASN)
		}
	}
	for _, v := range []string{"12345", "AS", "AS1234567890123", "AS-12345", ""} {
		if _, err := Parse(append(append([]string{}, base...), "-asn", v)...); err == nil {
			t.Errorf("Parse accepted an invalid ASN %q", v)
		}
	}
}

// TestIPModeGatesStages pins that IP and ASN runs do not run the domain stages.
func TestIPModeGatesStages(t *testing.T) {
	base := []string{"--scope", scopeFile(t), "--allow-private", "--yes"}

	opts := parse(t, append(append([]string{}, base...), "-ip", "192.0.2.0/29")...)
	if !opts.IPMode {
		t.Error("IPMode is false for an -ip run")
	}
	for _, s := range []string{"roots", "subs", "resolve", "content"} {
		if opts.StageEnabled(s) {
			t.Errorf("IP mode left the domain stage %s enabled", s)
		}
	}
	for _, s := range []string{"ports", "http"} {
		if !opts.StageEnabled(s) {
			t.Errorf("IP mode disabled %s, which it needs", s)
		}
	}

	if opts := parse(t, append(append([]string{}, base...), "-d", "example.com")...); opts.IPMode {
		t.Error("IPMode is true for a domain run")
	}
}

// TestExitStatusContract pins that each failure class maps to the documented
// status. Wrappers and CI branch on these numbers.
func TestExitStatusContract(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"usage: unknown flag", []string{"-d", "example.com", "--nonsense"}, 2},
		{"usage: bad profile", []string{"-d", "example.com", "--scope", scopeFile(t), "--profile", "quick"}, 2},
		{"scope: no allowlist", []string{"-d", "example.com", "--scope", filepath.Join(t.TempDir(), "nope.txt")}, 3},
		{"scope: target out of scope", []string{"-d", "attacker.test", "--scope", scopeFile(t)}, 3},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := Parse(tc.args...)
			if err == nil {
				err = opts.Precheck()
			}
			if err == nil {
				t.Fatalf("no error for %q, want status %d", tc.args, tc.want)
			}
			if got := StatusFor(err); got != tc.want {
				t.Errorf("StatusFor = %d, want %d (err = %v)", got, tc.want, err)
			}
		})
	}
}

// TestUnknownFlagIsRejected pins that a mistyped flag does not silently become
// a positional argument, which would otherwise scan something unexpected.
func TestUnknownFlagIsRejected(t *testing.T) {
	for _, args := range [][]string{
		{"--scopee", "x"},
		{"--dryrun"},
		{"--allowprivate"},
	} {
		_, err := Parse(args...)
		if err == nil {
			t.Errorf("Parse accepted a mistyped flag %q", args)
			continue
		}
		if got := RefusalKind(err); got != RefuseUsage {
			t.Errorf("RefusalKind(%q) = %v, want %v", args, got, RefuseUsage)
		}
	}
}

// TestDefaultsAreFilledIn pins that the default paths exist as values, so a
// missing --scope produces an authorization refusal rather than an empty path
// that happens to read.
func TestDefaultsAreFilledIn(t *testing.T) {
	opts := parse(t, "-d", "example.com")
	for name, v := range map[string]string{
		"ScopeFile": opts.ScopeFile,
		"EnvFile":   opts.EnvFile,
		"Output":    opts.Output,
	} {
		if v == "" {
			t.Errorf("%s defaulted to empty", name)
		}
	}
}

// TestPrecheckContactsNothing pins that validation is pure. A precheck that
// made a request would mean the authorization decision was not actually being
// made before the first packet.
func TestPrecheckContactsNothing(t *testing.T) {
	sf := scopeFile(t)

	if err := parse(t, "-d", "example.com", "--scope", sf).Precheck(); err != nil {
		t.Errorf("Precheck = %v, want nil", err)
	}
	if err := parse(t, "--scope", sf, "--why-denied", "example.com").Precheck(); err != nil {
		t.Errorf("Precheck for --why-denied = %v, want nil", err)
	}
}
