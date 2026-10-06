package cli

import (
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/config"
)

// This pins that a profile's pacing values are the ones that actually survive
// into Options, and that cli and config agree on what each profile means. It
// compares against config rather than hardcoded numbers, so editing a default
// in one place fails here instead of silently diverging.
func TestParsedPacingMatchesConfig(t *testing.T) {
	for _, profile := range []string{"fast", "normal", "exhaustive"} {
		o, err := Parse("-d", "example.com", "--scope", "cfg.txt", "--profile", profile)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", profile, err)
		}

		want := config.New()
		want.Profile = profile
		want.ApplyProfile()

		for _, c := range []struct {
			field    string
			got, exp int
		}{
			{"PortTop", o.PortTop, want.PortTop},
			{"PortRate", o.PortRate, want.PortRate},
			{"RateLimit", o.RateLimit, want.RateLimit},
			{"Timeout", o.Timeout, want.Timeout},
			{"KatanaDepth", o.KatanaDepth, want.KatanaDepth},
			{"NmapHostCap", o.NmapHostCap, want.NmapHostCap},
		} {
			if c.got != c.exp {
				t.Errorf("%s: %s = %d, config says %d", profile, c.field, c.got, c.exp)
			}
		}

		if o.NucleiSeverity != want.NucleiSeverity {
			t.Errorf("%s: NucleiSeverity = %q, config says %q",
				profile, o.NucleiSeverity, want.NucleiSeverity)
		}
		if o.NucleiRate != want.NucleiRate {
			t.Errorf("%s: NucleiRate = %d, config says %d", profile, o.NucleiRate, want.NucleiRate)
		}
	}
}

// The three concurrency fields are not profile driven, so nothing else fills
// them. A zero here reaches the tool invocations as a -c 0 argument.
func TestConcurrencyIsNeverZero(t *testing.T) {
	o, err := Parse("-d", "example.com", "--scope", "cfg.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range []struct {
		field string
		value int
	}{
		{"PortConc", o.PortConc},
		{"Threads", o.Threads},
		{"Jobs", o.Jobs},
	} {
		if c.value <= 0 {
			t.Errorf("%s = %d, must be positive", c.field, c.value)
		}
	}
}

func TestDefaultProfileMatchesConfig(t *testing.T) {
	o, err := Parse("-d", "example.com", "--scope", "cfg.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Profile != config.DefaultProfile {
		t.Errorf("default profile = %q, want %q", o.Profile, config.DefaultProfile)
	}
}
