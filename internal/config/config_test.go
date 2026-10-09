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

	for _, tc := range []struct {
		name string
		got  int
		min  int
	}{
		{"RateLimit", c.RateLimit, 1},
		{"Timeout", c.Timeout, 1},
		{"PortTop", c.PortTop, 1},
		{"PortRate", c.PortRate, 1},
		{"NucleiRate", c.NucleiRate, 1},
	} {
		if tc.got < tc.min {
			t.Errorf("%s = %d, want at least %d", tc.name, tc.got, tc.min)
		}
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

	if !fast.NucleiNoInteract {
		t.Error("fast should disable interactively-risky templates")
	}

	// Profile application must be repeatable.
	again := New()
	again.Profile = "exhaustive"
	again.ApplyProfile()
	if again.PortTop != exhaustive.PortTop {
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
