package stage

import (
	"context"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/run"
)

// TestPipelineGroupsMatchTheDocumentedOrder pins the pipeline shape.
//
// The two modes differ deliberately. In domain mode ports and HTTP are
// independent once resolve has finished, so they run together. In IP mode HTTP
// consumes the host:port pairs the port stage produced, so running them
// together would be a race.
func TestPipelineGroupsMatchTheDocumentedOrder(t *testing.T) {
	t.Run("domain mode", func(t *testing.T) {
		groups := pipelineGroups(false)
		got := groupNames(groups)

		want := []string{
			"targets",
			"roots",
			"subs",
			"resolve",
			"ports+http",
			"content+scan",
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("domain groups = %v, want %v", got, want)
		}
	})

	t.Run("ip mode serialises ports and http", func(t *testing.T) {
		groups := pipelineGroups(true)
		got := groupNames(groups)

		want := []string{
			"targets",
			"roots+subs+resolve",
			"ports",
			"http",
			"content+scan",
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("ip groups = %v, want %v", got, want)
		}
	})

	t.Run("ports and http are never in one group in ip mode", func(t *testing.T) {
		for _, g := range pipelineGroups(true) {
			if len(g) != 2 {
				continue
			}
			names := groupNames([][]stageEntry{g})[0]
			if strings.Contains(names, "ports") && strings.Contains(names, "http") {
				t.Errorf("group %q runs ports and http together in IP mode", names)
			}
		}
	})

	t.Run("content and scan are concurrent in both modes", func(t *testing.T) {
		for _, ipMode := range []bool{false, true} {
			found := false
			for _, g := range pipelineGroups(ipMode) {
				if len(g) == 2 && groupNames([][]stageEntry{g})[0] == "content+scan" {
					found = true
				}
			}
			if !found {
				t.Errorf("ipMode=%v: content and scan do not run as a concurrent pair", ipMode)
			}
		}
	})
}

// groupNames renders each group as a readable label.
func groupNames(groups [][]stageEntry) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		names := make([]string, 0, len(g))
		for _, s := range g {
			names = append(names, s.name)
		}
		out = append(out, strings.Join(names, "+"))
	}
	return out
}

// TestConcurrentStagesAreAllRecorded pins that a backgrounded stage is recorded
// by the parent when it is joined.
//
// A goroutine appending to the shared stage list from inside itself would race,
// and a stage that finished would sometimes be missing from the manifest, which
// is the failure shape this test exists to catch.
func TestConcurrentStagesAreAllRecorded(t *testing.T) {
	r := newHarness(t, standardAllow, standardDeny).env.Run

	// Two slow stages so the ordering of the joins is exercised.
	slow := make(chan struct{})
	a, err := r.StageAsync("alpha", func() error {
		<-slow
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.StageAsync("beta", func() error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := b.Wait(); err != nil {
		t.Errorf("beta reported %v", err)
	}
	close(slow)
	if err := a.Wait(); err != nil {
		t.Errorf("alpha reported %v", err)
	}

	// Both are recorded, in the order they were started.
	st := r.Stages()
	if len(st) != 2 {
		t.Fatalf("stages = %d (%v), want 2", len(st), stageNames(st))
	}
	if st[0].Name != "alpha" || st[1].Name != "beta" {
		t.Errorf("stage order = %v, want alpha then beta", stageNames(st))
	}
}

// TestConcurrentNotesStayWithTheirOwnStage pins that two concurrent stages
// cannot describe each other.
//
// A note is set from inside the running function, before its record exists. If
// the note were keyed by "most recent record" or by a single shared current
// stage, one of these would land on the other.
func TestConcurrentNotesStayWithTheirOwnStage(t *testing.T) {
	r := newHarness(t, standardAllow, standardDeny).env.Run

	a, err := r.StageAsync("alpha", func() error {
		r.SetNote("alpha", "alpha note")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.StageAsync("beta", func() error {
		r.SetNote("beta", "beta note")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Wait()
	_ = b.Wait()

	notes := map[string]string{}
	for _, s := range r.Stages() {
		notes[s.Name] = s.Note
	}
	if notes["alpha"] != "alpha note" {
		t.Errorf("alpha note = %q, want %q", notes["alpha"], "alpha note")
	}
	if notes["beta"] != "beta note" {
		t.Errorf("beta note = %q, want %q", notes["beta"], "beta note")
	}
}

// TestSkippedStageIsRecordedOnce pins that a stage which declines to apply is
// recorded a single time.
//
// Calling Skip from inside a stage function and then also recording the return
// value produced two entries for one stage, which made a manifest look like it
// had run a stage twice.
func TestSkippedStageIsRecordedOnce(t *testing.T) {
	r := newHarness(t, standardAllow, standardDeny).env.Run

	err := r.Stage("targets", func() error {
		r.SetNote("targets", "does not apply here")
		return run.ErrSkip
	})
	if err != nil {
		t.Errorf("Stage returned %v for a skipped stage; it should report success", err)
	}

	st := r.Stages()
	if len(st) != 1 {
		t.Fatalf("stages = %d (%v), want exactly 1", len(st), stageNames(st))
	}
	if st[0].Status != run.StatusSkipped {
		t.Errorf("status = %q, want %q", st[0].Status, run.StatusSkipped)
	}
	if st[0].Note != "does not apply here" {
		t.Errorf("note = %q, want the reason", st[0].Note)
	}
	if st[0].ExitCode != 0 {
		t.Errorf("exit_code = %d for a skipped stage, want 0", st[0].ExitCode)
	}
	if r.Failed() != 0 {
		t.Errorf("Failed() = %d, want 0; a skipped stage is not a failure", r.Failed())
	}
}

// TestTargetsStageRunsOnceInBothModes exercises the whole pipeline shape.
func TestTargetsStageRunsOnceInBothModes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ipMode  bool
		wantRun bool
	}{
		{"domain mode skips it", false, false},
		{"ip mode runs it", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "192.0.2.0/29\n", "")
			h.env.Opts.IPMode = tc.ipMode
			h.env.Opts.IPTarget = "192.0.2.0/29"

			err := Run(context.Background(), h.env, func(string) bool { return true })
			if tc.ipMode && err != nil {
				t.Logf("pipeline reported %v, which is expected with no tools installed", err)
			}

			count := 0
			for _, s := range h.env.Run.Stages() {
				if s.Name == "targets" {
					count++
				}
			}
			if count != 1 {
				t.Errorf("targets recorded %d times, want exactly 1", count)
			}
		})
	}
}

func stageNames(st []run.Stage) []string {
	out := make([]string, 0, len(st))
	for _, s := range st {
		out = append(out, s.Name)
	}
	return out
}
