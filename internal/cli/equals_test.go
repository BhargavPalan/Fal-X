package cli

import "testing"

// The flag package accepts -flag=value and so does every other command line
// tool. A parser that rejects that spelling reads as a defect rather than a rule
// the operator has to know, and it does so at the worst moment: mid incident,
// when someone is pasting a command from memory.

func TestEqualsFormParses(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		check func(o *Options) bool
	}{
		{"short form", []string{"-d=example.com", "--scope=cfg.txt"},
			func(o *Options) bool { return o.Domain == "example.com" && o.ScopeFile == "cfg.txt" }},
		{"long form", []string{"--domain=example.com", "--scope=cfg.txt"},
			func(o *Options) bool { return o.Domain == "example.com" }},
		{"space form still works", []string{"-d", "example.com", "--scope", "cfg.txt"},
			func(o *Options) bool { return o.Domain == "example.com" && o.ScopeFile == "cfg.txt" }},
		{"value containing an equals sign", []string{"-d=example.com", "--scope=cfg.txt", "--profile=fast"},
			func(o *Options) bool { return o.Profile == "fast" }},
		{"short flag with attached value", []string{"-ip=192.0.2.0/24", "--scope=cfg.txt"},
			func(o *Options) bool { return o.IPTarget == "192.0.2.0/24" }},
		{"multiple attached values", []string{"-d=example.com", "--scope=cfg.txt", "--stages=roots,ports"},
			func(o *Options) bool { return len(o.Stages()) == 2 }},
	}
	for _, c := range cases {
		o, err := Parse(c.args...)
		if err != nil {
			t.Errorf("%s: unexpected error for %v: %v", c.name, c.args, err)
			continue
		}
		if !c.check(o) {
			t.Errorf("%s: %v parsed to unexpected values", c.name, c.args)
		}
	}
}

func TestEqualsFormStillValidates(t *testing.T) {
	// Attaching a value must not bypass any check the space form applies.
	for _, c := range []struct {
		name string
		args []string
	}{
		{"profile", []string{"-d=example.com", "--scope=cfg.txt", "--profile=bogus"}},
		{"ports", []string{"-d=example.com", "--scope=cfg.txt", "--ports=notaport"}},
		{"stages", []string{"-d=example.com", "--scope=cfg.txt", "--stages=nonsense"}},
		{"ip", []string{"-d=example.com", "--scope=cfg.txt", "-ip=999.1.1.1"}},
		{"asn", []string{"-asn=nope", "--scope=cfg.txt"}},
	} {
		if _, err := Parse(c.args...); err == nil {
			t.Errorf("%s: expected a usage error for %v", c.name, c.args)
		}
	}
}

// Silently dropping the value would turn --dry-run=false into --dry-run, which
// is a scan the operator explicitly asked to skip.
func TestSwitchRejectsAttachedValue(t *testing.T) {
	for _, arg := range []string{"--dry-run=false", "--brute=1", "--yes=maybe", "--allow-private=x", "--quiet=0"} {
		if _, err := Parse("-d", "example.com", "--scope", "cfg.txt", arg); err == nil {
			t.Errorf("expected %s to be rejected", arg)
		}
	}
}

// An empty value is meaningful for some flags, --stages for one, where it means
// the default rather than nothing. So emptiness is not rejected outright. What
// must hold is that the two spellings agree, or the choice of one silently
// changes the meaning of the other.
func TestAttachedAndSpacedValuesAgree(t *testing.T) {
	for _, c := range []struct {
		name   string
		joined []string
		spaced []string
	}{
		{"empty scope", []string{"-d=example.com", "--scope="}, []string{"-d", "example.com", "--scope", ""}},
		{"empty stages", []string{"-d=example.com", "--scope=c.txt", "--stages="}, []string{"-d", "example.com", "--scope", "c.txt", "--stages", ""}},
		{"value with a comma", []string{"-d=example.com", "--scope=c.txt", "--stages=roots,ports"}, []string{"-d", "example.com", "--scope", "c.txt", "--stages", "roots,ports"}},
	} {
		a, aerr := Parse(c.joined...)
		b, berr := Parse(c.spaced...)
		if (aerr == nil) != (berr == nil) {
			t.Errorf("%s: joined form err=%v but spaced form err=%v", c.name, aerr, berr)
			continue
		}
		if aerr != nil {
			continue
		}
		if a.ScopeFile != b.ScopeFile || a.Domain != b.Domain || a.Profile != b.Profile {
			t.Errorf("%s: joined form parsed differently from spaced form", c.name)
		}
		if len(a.Stages()) != len(b.Stages()) {
			t.Errorf("%s: joined form enabled %d stages, spaced enabled %d",
				c.name, len(a.Stages()), len(b.Stages()))
		}
	}
}
