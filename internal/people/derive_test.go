package people

import "testing"

func TestSplitEmail(t *testing.T) {
	cases := []struct {
		in            string
		local, domain string
		ok            bool
	}{
		{"jane.doe@acme.com", "jane.doe", "acme.com", true},
		{"Jane.Doe@Acme.COM", "jane.doe", "acme.com", true},
		{"jane+newsletter@acme.com", "jane", "acme.com", true},
		{"info@sub.acme.co.uk", "info", "sub.acme.co.uk", true},
		{"not-an-email", "", "", false},
		{"@acme.com", "", "", false},
		{"jane@", "", "", false},
		{"jane@localhost", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		local, domain, ok := splitEmail(c.in)
		if ok != c.ok || local != c.local || domain != c.domain {
			t.Errorf("splitEmail(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.in, local, domain, ok, c.local, c.domain, c.ok)
		}
	}
}

func TestClassifyLocal(t *testing.T) {
	cases := map[string]string{
		"jane.doe":   "personal",
		"jane":       "personal", // a human mailbox, even though no full name is read from it
		"jdoe":       "personal", // likewise a personal mailbox; just not a nameable contact
		"info":       "role",
		"no-reply":   "role",
		"security":   "role",
		"postmaster": "role",
		"it.support": "role", // a compound of role tokens is a shared inbox, not a person
		"no.reply":   "role",
		"sales.team": "role",
		"a1b2c3":     "other", // a digit marks it an opaque id, not a person
		"build123":   "other",
		"":           "other",
	}
	for local, want := range cases {
		if got := classifyLocal(local); got != want {
			t.Errorf("classifyLocal(%q) = %q, want %q", local, got, want)
		}
	}
}

func TestPersonFromLocal(t *testing.T) {
	cases := []struct {
		local           string
		display, format string
		ok              bool
	}{
		{"jane.doe", "Jane Doe", "{first}.{last}", true},
		{"jane_doe", "Jane Doe", "{first}_{last}", true},
		{"jane-doe", "Jane Doe", "{first}-{last}", true},
		{"jane", "", "", false},                          // a single token is not a confident full name
		{"JANE.DOE", "Jane Doe", "{first}.{last}", true}, // tolerant of case, though callers lowercase first
		{"jdoe", "", "", false},                          // cannot split an initials blob
		{"it.support", "", "", false},                    // compound role address, not a person
		{"no.reply", "", "", false},                      // automated-sender compound
		{"mailer.daemon", "", "", false},                 // automated-sender compound
		{"help.desk", "", "", false},                     // shared-inbox compound
		{"j.d", "", "", false},                           // tokens too short to trust
		{"jane.m.doe", "", "", false},                    // three parts are ambiguous
		{"info", "", "", false},                          // role word, never a person
		{"jane2.doe", "", "", false},                     // a digit means it is not a clean name
		{"", "", "", false},
	}
	for _, c := range cases {
		display, format, ok := personFromLocal(c.local)
		if ok != c.ok || display != c.display || format != c.format {
			t.Errorf("personFromLocal(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.local, display, format, ok, c.display, c.format, c.ok)
		}
	}
}

func TestDominantIsDeterministic(t *testing.T) {
	// Two formats tie at 3; the tie breaks by format string, so the result is stable.
	counts := map[string]int{"{first}.{last}": 3, "{first}": 1, "{first}_{last}": 3}
	best, n := dominant(counts)
	if n != 3 {
		t.Fatalf("dominant count = %d, want 3", n)
	}
	if best != "{first}.{last}" {
		t.Errorf("dominant = %q, want %q (ties break by format string)", best, "{first}.{last}")
	}
}
