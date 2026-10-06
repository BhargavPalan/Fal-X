package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewIsSelfConsistent checks the defaults actually agree with each other.
//
// These are the numbers a run is governed by, and nothing forces them to be
// sensible: a port rate of zero or a rate limit below the connect timeout is
// reachable purely by editing this file.
func TestNewIsSelfConsistent(t *testing.T) {
	c := New()

	if c.Profile != "normal" {
		t.Errorf("Profile = %q, want normal", c.Profile)
	}
	if !ValidProfile(c.Profile) {
		t.Errorf("default profile %q is not accepted by ValidProfile", c.Profile)
	}

	// Every stage is on by default. A stage silently defaulting to off would
	// make a plain scan quietly incomplete.
	for name, on := range map[string]bool{
		"targets": c.DoTargets, "roots": c.DoRoots, "subs": c.DoSubs,
		"resolve": c.DoResolve, "ports": c.DoPorts, "http": c.DoHTTP,
		"content": c.DoContent, "scan": c.DoScan,
	} {
		if !on {
			t.Errorf("stage %s is off by default", name)
		}
	}

	// The optional, slower stages must be opt-in. Brute force and directory
	// brute force in particular generate real traffic against a third party.
	for name, on := range map[string]bool{
		"brute": c.DoBrute, "dirs": c.DoDirs, "amass": c.DoAmass,
		"nmap": c.DoNmap, "censys": c.DoCensys,
	} {
		if on {
			t.Errorf("optional stage %s is on by default", name)
		}
	}

	// Authorization must not be pre-acknowledged.
	if c.AuthAck {
		t.Error("AuthAck defaults to true; authorization must be explicit")
	}
	if c.AllowAny || c.AllowPrivate {
		t.Error("scope overrides default to permissive")
	}

	for _, tc := range []struct {
		name string
		got  int
		min  int
	}{
		{"RateLimit", c.RateLimit, 1},
		{"Timeout", c.Timeout, 1},
		{"PortTop", c.PortTop, 1},
		{"PortRate", c.PortRate, 1},
		{"MaxTargets", c.MaxTargets, 1},
		{"MaxURLs", c.MaxURLs, 1},
		{"NucleiRate", c.NucleiRate, 1},
	} {
		if tc.got < tc.min {
			t.Errorf("%s = %d, want at least %d", tc.name, tc.got, tc.min)
		}
	}

	// The run has to be bounded in wall-clock time as well as in work.
	if c.MaxRuntime <= 0 {
		t.Error("MaxRuntime is not positive; a run could never be cut off")
	}
}

// TestDetectResourcesClampsLow pins the zero-core case. Reporting zero cores
// happens on constrained containers, and multiplying it through would produce a
// zero concurrency that some tools interpret as unlimited.
func TestDetectResourcesClampsLow(t *testing.T) {
	c := New()
	c.DetectResources(0)

	if c.THREADS < 1 || c.JOBS < 1 || c.PortConc < 1 {
		t.Errorf("zero cores produced non-positive concurrency: threads=%d jobs=%d portconc=%d",
			c.THREADS, c.JOBS, c.PortConc)
	}
	if c.NucleiConcurrency < 1 {
		t.Errorf("NucleiConcurrency = %d, want at least 1", c.NucleiConcurrency)
	}
	if c.JSParallel < 1 {
		t.Errorf("JSParallel = %d, want at least 1", c.JSParallel)
	}
}

// TestDetectResourcesScales pins that concurrency tracks the core count.
func TestDetectResourcesScales(t *testing.T) {
	c := New()
	c.DetectResources(8)
	if c.THREADS != 80 {
		t.Errorf("THREADS = %d, want 80", c.THREADS)
	}
	if c.JOBS != 16 {
		t.Errorf("JOBS = %d, want 16", c.JOBS)
	}

	// An explicit value must be respected rather than overwritten.
	d := New()
	d.NucleiConcurrency = 3
	d.DetectResources(64)
	if d.NucleiConcurrency != 3 {
		t.Errorf("DetectResources overwrote an explicit NucleiConcurrency: %d", d.NucleiConcurrency)
	}
}

// TestApplyProfile pins the direction of each profile.
//
// The point is that exhaustive is a superset of normal and fast is a subset.
// If a profile ever stops a stage that the default runs, choosing it would
// silently reduce coverage.
func TestApplyProfile(t *testing.T) {
	normal := New()
	normal.ApplyProfile()

	fast := New()
	fast.Profile = "fast"
	fast.ApplyProfile()

	exhaustive := New()
	exhaustive.Profile = "exhaustive"
	exhaustive.ApplyProfile()

	if fast.PortTop >= normal.PortTop {
		t.Errorf("fast PortTop %d should be smaller than normal %d", fast.PortTop, normal.PortTop)
	}
	if exhaustive.PortTop <= normal.PortTop {
		t.Errorf("exhaustive PortTop %d should exceed normal %d", exhaustive.PortTop, normal.PortTop)
	}
	if exhaustive.PortTop != 65535 {
		t.Errorf("exhaustive PortTop = %d, want a full sweep", exhaustive.PortTop)
	}

	if !exhaustive.DoBrute || !exhaustive.DoDirs {
		t.Error("exhaustive should enable brute force and directory discovery")
	}
	if fast.DoBrute || fast.DoDirs {
		t.Error("fast should not enable brute force or directory discovery")
	}
	if !fast.NucleiNoInteract {
		t.Error("fast should disable interactively-risky templates")
	}

	// Profile application must be repeatable.
	again := New()
	again.Profile = "exhaustive"
	again.ApplyProfile()
	if again.PortTop != exhaustive.PortTop || again.DoBrute != exhaustive.DoBrute {
		t.Error("ApplyProfile is not deterministic across calls")
	}
}

// TestValidProfile pins that an unknown profile is rejected rather than
// silently behaving as normal, which would make a typo look like a request for
// a faster scan.
func TestValidProfile(t *testing.T) {
	for _, name := range []string{"fast", "normal", "exhaustive"} {
		if !ValidProfile(name) {
			t.Errorf("ValidProfile(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"", "Fast", "FAST", "quick", "deep", "normal "} {
		if ValidProfile(name) {
			t.Errorf("ValidProfile(%q) = true, want false", name)
		}
	}
}

// TestHomeHonoursEnv pins that FALX_HOME wins, since that is how the test
// suite and a container image point at a different tree.
func TestHomeHonoursEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FALX_HOME", dir)

	if got := Home(); got != dir {
		t.Errorf("Home() = %q, want %q", got, dir)
	}
	c := New()
	if c.Home != dir {
		t.Errorf("Config.Home = %q, want %q", c.Home, dir)
	}
	for _, path := range []string{c.Output, c.EnvFile, c.ScopeFile, c.OutOfScopeFile} {
		if !filepath.IsAbs(path) {
			t.Errorf("path %q is not absolute", path)
		}
		if !strings.HasPrefix(path, dir) {
			t.Errorf("path %q is not under FALX_HOME %q", path, dir)
		}
	}
}

// TestHomeFindsModuleRoot pins the fallback, which must work from a test binary
// running anywhere inside the tree.
func TestHomeFindsModuleRoot(t *testing.T) {
	t.Setenv("FALX_HOME", "")

	got := Home()
	if _, err := os.Stat(filepath.Join(got, "go.mod")); err != nil {
		t.Fatalf("Home() = %q, which has no go.mod: %v", got, err)
	}
}
