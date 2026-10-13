package monitor

import (
	"strings"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/store"
)

func TestEventsClassifiesBySeverity(t *testing.T) {
	now := time.Now()
	added := []store.DiffRow{
		{Kind: "host", Identifier: "new.example.com", FirstSeen: now},
		{Kind: "credential", Identifier: "secret:x", FirstSeen: now},
	}
	changed := []store.DiffFact{
		{Kind: "host", Identifier: "h", Key: "finding", Value: "high exposed-git-repository"},
		{Kind: "domain", Identifier: "d", Key: "exposure", Value: "email_spoofable"},
		{Kind: "host", Identifier: "h", Key: "verification", Value: "confirmed takeover — unclaimed"},
		{Kind: "host", Identifier: "h", Key: "tech", Value: "nginx"},
	}

	got := map[string]string{} // "type:key:detail" -> severity
	var sawGone bool
	for _, e := range Events(added, changed) {
		if e.Type == "gone" {
			sawGone = true
		}
		got[e.Type+":"+e.Key+":"+e.Detail] = e.Severity
	}
	if sawGone {
		t.Error("Events must not emit 'gone' alerts (disappearance is unreliable in a re-scan)")
	}
	cases := map[string]string{
		"added:new.example.com:":                                "info",
		"added:secret:x:":                                       "high", // a new credential is a lead, not noise
		"changed:h:finding=high exposed-git-repository":         "high",
		"changed:d:exposure=email_spoofable":                    "high",
		"changed:h:verification=confirmed takeover — unclaimed": "high",
		"changed:h:tech=nginx":                                  "info",
	}
	for k, want := range cases {
		if got[k] != want {
			t.Errorf("event %q severity = %q, want %q", k, got[k], want)
		}
	}
}

func TestFormatOrdersBySeverityAndHandlesEmpty(t *testing.T) {
	if got := Format(nil); got != "no changes" {
		t.Errorf("empty Format = %q, want \"no changes\"", got)
	}
	out := Format([]ChangeEvent{
		{Type: "added", Kind: "host", Key: "low.example.com", Severity: "info"},
		{Type: "changed", Kind: "host", Key: "bad.example.com", Detail: "exposure=leaked_secret", Severity: "critical"},
	})
	lines := strings.Split(out, "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "[critical]") {
		t.Errorf("Format did not sort most-severe first:\n%s", out)
	}
}
