package run

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// newTestRun returns an initialised run writing into a temporary directory.
func newTestRun(t *testing.T) *Run {
	t.Helper()
	r, err := Init(t.TempDir(), "example.com", "20261003-123456")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return r
}

// TestStageRecordsRealOutcome pins that a stage's status comes from what
// actually happened rather than from an unqualified success message.
// A stage whose command failed must not be able to report itself as succeeded.
func TestStageRecordsRealOutcome(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		r := newTestRun(t)
		if err := r.Stage("roots", func() error { return nil }); err != nil {
			t.Fatalf("Stage returned %v, want nil", err)
		}

		st := r.Stages()[0]
		if st.Status != StatusSucceeded {
			t.Errorf("status = %q, want %q", st.Status, StatusSucceeded)
		}
		if st.ExitCode != 0 {
			t.Errorf("exit_code = %d, want 0", st.ExitCode)
		}
		if st.Name != "roots" {
			t.Errorf("name = %q, want roots", st.Name)
		}
	})

	t.Run("failure", func(t *testing.T) {
		r := newTestRun(t)
		boom := errors.New("tool exited 1")
		err := r.Stage("ports", func() error { return boom })
		if err == nil {
			t.Fatal("Stage returned nil for a failing command")
		}
		if !errors.Is(err, boom) {
			t.Errorf("Stage returned %v, want it to wrap the command's error", err)
		}

		st := r.Stages()[0]
		if st.Status != StatusFailed {
			t.Errorf("status = %q, want %q", st.Status, StatusFailed)
		}
		if st.ExitCode == 0 {
			t.Error("exit_code = 0 for a failed stage")
		}
	})
}

// TestStageFailurePropagates pins that a caller cannot accidentally continue
// past a failure.
func TestStageFailurePropagates(t *testing.T) {
	r := newTestRun(t)
	_ = r.Stage("a", func() error { return errors.New("boom") })

	if r.Failed() != 1 {
		t.Errorf("Failed() = %d, want 1", r.Failed())
	}
	if err := r.Finalise(); err == nil {
		t.Error("Finalise returned nil despite a failed stage")
	}
}

// TestStageSkip pins that a stage that did not run is recorded as skipped with
// a reason, rather than silently absent.
//
// A stage missing from the manifest and a stage recorded as skipped are
// different facts, and the report has to be able to tell them apart.
func TestStageSkip(t *testing.T) {
	r := newTestRun(t)
	r.Skip("content", "not requested")

	st := r.Stages()[0]
	if st.Status != StatusSkipped {
		t.Errorf("status = %q, want %q", st.Status, StatusSkipped)
	}
	if st.Note != "not requested" {
		t.Errorf("note = %q, want the skip reason", st.Note)
	}
	if st.ExitCode != 0 {
		t.Errorf("exit_code = %d for a skipped stage, want 0", st.ExitCode)
	}
}

// TestEmptyOutputIsNotAMissingOutput is the distinction stages.json depends on.
//
// An empty file means the stage ran and found nothing. A missing file means the
// stage never got that far. Deleting empty files to tidy up destroys the only
// difference between a clean result and a crashed stage, so the recorder has to
// distinguish them.
func TestEmptyOutputIsNotAMissingOutput(t *testing.T) {
	r := newTestRun(t)
	dir := t.TempDir()

	found := filepath.Join(dir, "found_empty.txt")
	if err := os.WriteFile(found, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(dir, "never_written.txt")

	// The stage ran and wrote one empty file. The count is declared from inside
	// the stage function, which is where a stage actually knows what it wrote.
	if err := r.Stage("resolve", func() error {
		r.RecordOutputs("resolve", found, absent)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if got := r.Stages()[0].Outputs; got != 1 {
		t.Errorf("outputs = %d, want 1: an empty file is still an output", got)
	}
}

// TestInputsAreRecorded pins that a stage declares how much it was given, so a
// result can be judged against its input size.
func TestInputsAreRecorded(t *testing.T) {
	r := newTestRun(t)

	r.SetInputs(42)
	if err := r.Stage("subs", func() error { return nil }); err != nil {
		t.Fatal(err)
	}

	if got := r.Stages()[0].Inputs; got != 42 {
		t.Errorf("inputs = %d, want 42", got)
	}

	// The count must not leak into the next stage.
	r.SetInputs(7)
	if err := r.Stage("http", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := r.Stages()[1].Inputs; got != 7 {
		t.Errorf("inputs = %d for the second stage, want 7", got)
	}
}

// TestStagesJSONIsTheAuthority pins the manifest shape, because it is what
// other tools read.
//
// The field names are a compatibility surface. Renaming one silently breaks
// every consumer that reads a run directory.
func TestStagesJSONIsTheAuthority(t *testing.T) {
	r := newTestRun(t)

	_ = r.Stage("roots", func() error { return nil })
	r.SetInputs(3)
	_ = r.Stage("subs", func() error { return errors.New("boom") })
	r.Skip("scan", "skipped by --skip-scan")

	if err := r.WriteStages(); err != nil {
		t.Fatalf("WriteStages: %v", err)
	}

	path := filepath.Join(r.Dir, "stages.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read stages.json: %v", err)
	}

	// It has to parse. A manifest assembled by string formatting breaks here, and
	// it is assembled by marshalling rather than formatting precisely so that a
	// value containing a quote or a newline still produces valid JSON.
	var doc struct {
		SchemaVersion int    `json:"schema_version"`
		RunID         string `json:"run_id"`
		Stages        []struct {
			Name            string `json:"name"`
			Status          string `json:"status"`
			ExitCode        int    `json:"exit_code"`
			DurationSeconds int64  `json:"duration_seconds"`
			Inputs          int    `json:"inputs"`
			Outputs         int    `json:"outputs"`
			Note            string `json:"note"`
		} `json:"stages"`
		Failed               int   `json:"failed"`
		TotalDurationSeconds int64 `json:"total_duration_seconds"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("stages.json does not parse: %v\n%s", err, b)
	}

	if doc.SchemaVersion == 0 {
		t.Error("schema_version is missing")
	}
	if doc.RunID != r.ID {
		t.Errorf("run_id = %q, want %q", doc.RunID, r.ID)
	}
	if len(doc.Stages) != 3 {
		t.Fatalf("stages = %d, want 3", len(doc.Stages))
	}
	if doc.Failed != 1 {
		t.Errorf("failed = %d, want 1", doc.Failed)
	}

	want := []struct {
		name, status string
		inputs       int
	}{
		{"roots", string(StatusSucceeded), 0},
		{"subs", string(StatusFailed), 3},
		{"scan", string(StatusSkipped), 0},
	}
	for i, w := range want {
		got := doc.Stages[i]
		if got.Name != w.name {
			t.Errorf("stage %d name = %q, want %q", i, got.Name, w.name)
		}
		if got.Status != w.status {
			t.Errorf("stage %s status = %q, want %q", w.name, got.Status, w.status)
		}
		if got.Inputs != w.inputs {
			t.Errorf("stage %s inputs = %d, want %d", w.name, got.Inputs, w.inputs)
		}
	}
	if doc.Stages[2].Note != "skipped by --skip-scan" {
		t.Errorf("skip note = %q", doc.Stages[2].Note)
	}
}

// TestRunJSONRecordsTheAuthorizedScope pins that a run records the scope it was
// authorised under.
//
// A result is only meaningful alongside the authorization that permitted it.
// Recording the scope fingerprint means a later reader can tell which allowlist
// produced it.
func TestRunJSONRecordsTheAuthorizedScope(t *testing.T) {
	r := newTestRun(t)
	r.SetScope("example.com\n*.wild.test\n", "admin.example.com\n")
	r.SetTarget("example.com")

	if err := r.WriteManifest(); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(r.Dir, "run.json"))
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}

	var doc struct {
		RunID     string `json:"run_id"`
		Target    string `json:"target"`
		Stamp     string `json:"stamp"`
		Allowlist string `json:"scope_allowlist"`
		Denylist  string `json:"scope_denylist"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("run.json does not parse: %v\n%s", err, b)
	}

	if doc.Target != "example.com" {
		t.Errorf("target = %q", doc.Target)
	}
	if doc.Allowlist == "" {
		t.Error("run.json records no allowlist, so the authorization cannot be audited")
	}
	if doc.Denylist == "" {
		t.Error("run.json records no denylist")
	}
}

// TestRunDirectoryIsPrivate pins that the run directory is not world readable.
//
// A run directory holds findings, which routinely include secret-shaped
// matches. Mode 0700 keeps that off other accounts on a shared host.
func TestRunDirectoryIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are not meaningful on Windows")
	}
	r := newTestRun(t)

	fi, err := os.Stat(r.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("run directory mode is %04o, want no group or world access", perm)
	}
}

// TestConcurrentStagesAreJoined pins that backgrounded stages are recorded by
// the parent.
//
// A stage started in a goroutine cannot update the parent's record from inside
// itself, so the record has to be made where the result is joined. Getting this
// wrong is how a stage ends up missing from the manifest while still having run.
func TestConcurrentStagesAreJoined(t *testing.T) {
	r := newTestRun(t)

	// The two real concurrent pairs are ports|http and content|scan.
	portsDone, err := r.StageAsync("ports", func() error {
		time.Sleep(10 * time.Millisecond)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	httpDone, err := r.StageAsync("http", func() error {
		return errors.New("probe failed")
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := portsDone.Wait(); err != nil {
		t.Errorf("ports stage reported %v, want nil", err)
	}
	httpErr := httpDone.Wait()
	if httpErr == nil {
		t.Error("http stage reported success despite failing")
	}

	// Both must be recorded, in the order they were started.
	st := r.Stages()
	if len(st) != 2 {
		t.Fatalf("stages = %d, want 2; a backgrounded stage went unrecorded", len(st))
	}
	if st[0].Name != "ports" || st[1].Name != "http" {
		t.Errorf("stage order = %q, %q; want ports, http", st[0].Name, st[1].Name)
	}
	if st[0].Status != StatusSucceeded {
		t.Errorf("ports status = %q, want succeeded", st[0].Status)
	}
	if st[1].Status != StatusFailed {
		t.Errorf("http status = %q, want failed", st[1].Status)
	}
	if r.Failed() != 1 {
		t.Errorf("Failed() = %d, want 1", r.Failed())
	}
}

// TestStageAsyncRecordsPanicAsFailure pins that a panicking tool is recorded as
// a failed stage rather than crashing the run without a manifest.
func TestStageAsyncRecordsPanicAsFailure(t *testing.T) {
	r := newTestRun(t)

	done, err := r.StageAsync("scan", func() error {
		panic("tool exploded")
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := done.Wait(); err == nil {
		t.Error("Wait returned nil for a panicking stage")
	}

	st := r.Stages()
	if len(st) != 1 {
		t.Fatalf("stages = %d, want 1", len(st))
	}
	if st[0].Status != StatusFailed {
		t.Errorf("status = %q, want %q", st[0].Status, StatusFailed)
	}
}

// TestNoteAndOutputsAttachToTheRunningStage is a regression test.
//
// A stage calls SetNote and RecordOutputs from inside its own function, which is
// before its record exists. Attaching to "the most recent record" therefore
// wrote each note onto the previous stage, so stages.json described the resolve
// stage with the ports stage's outcome.
func TestNoteAndOutputsAttachToTheRunningStage(t *testing.T) {
	r := newTestRun(t)
	dir := t.TempDir()

	firstOut := filepath.Join(dir, "first.txt")
	secondOut := filepath.Join(dir, "second.txt")
	for _, p := range []string{firstOut, secondOut} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	_ = r.Stage("first", func() error {
		r.SetNote("first", "first note")
		r.RecordOutputs("first", firstOut)
		return nil
	})
	_ = r.Stage("second", func() error {
		r.SetNote("second", "second note")
		r.RecordOutputs("second", secondOut)
		return nil
	})

	st := r.Stages()
	if len(st) != 2 {
		t.Fatalf("stages = %d, want 2", len(st))
	}
	if st[0].Note != "first note" {
		t.Errorf("stage %q note = %q, want %q", st[0].Name, st[0].Note, "first note")
	}
	if st[1].Note != "second note" {
		t.Errorf("stage %q note = %q, want %q", st[1].Name, st[1].Note, "second note")
	}
	if st[0].Outputs != 1 || st[1].Outputs != 1 {
		t.Errorf("outputs = %d, %d; want 1 each", st[0].Outputs, st[1].Outputs)
	}
}

// TestNoteOnAStageThatDidNotRun is harmless rather than misfiled.
//
// A note for a stage name that never ran has nothing to attach to, and is
// dropped rather than landing on whatever stage happens to be last.
func TestNoteOnAStageThatDidNotRun(t *testing.T) {
	r := newTestRun(t)
	r.SetNote("never-ran", "orphan note")

	if err := r.Stage("only", func() error { return nil }); err != nil {
		t.Fatal(err)
	}

	if got := r.Stages()[0].Note; got != "" {
		t.Errorf("note = %q, want an orphan note dropped", got)
	}
}

// TestFinaliseReportsEveryStage pins that the manifest is written even when a
// stage failed, because the failure record is the reason to read it.
func TestFinaliseReportsEveryStage(t *testing.T) {
	r := newTestRun(t)
	_ = r.Stage("roots", func() error { return nil })
	_ = r.Stage("ports", func() error { return errors.New("boom") })
	_ = r.Stage("http", func() error { return nil })

	err := r.Finalise()
	if err == nil {
		t.Fatal("Finalise returned nil despite a failure")
	}

	// Both artefacts exist regardless.
	for _, name := range []string{"run.json", "stages.json"} {
		if _, statErr := os.Stat(filepath.Join(r.Dir, name)); statErr != nil {
			t.Errorf("%s was not written: %v", name, statErr)
		}
	}

	// A caller has to be able to see which stage failed.
	if !strings.Contains(err.Error(), "ports") {
		t.Errorf("Finalise error %q does not name the failed stage", err)
	}
}

// TestSummaryLine pins the one-line human summary.
func TestSummaryLine(t *testing.T) {
	r := newTestRun(t)
	_ = r.Stage("roots", func() error { return nil })
	_ = r.Stage("subs", func() error { return nil })
	r.Skip("scan", "not requested")

	got := r.SummaryLine()
	for _, want := range []string{"2", "1", "scan"} {
		if !strings.Contains(got, want) {
			t.Errorf("SummaryLine %q does not mention %q", got, want)
		}
	}
}
