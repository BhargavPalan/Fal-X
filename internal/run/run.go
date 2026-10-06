// Package run records what a run did.
//
// It owns the run manifest and the stage manifest, which together are the
// authority on whether a run completed. The log says what happened; these files
// say what is true.
//
// The distinction the whole package exists to preserve:
//
//   - An empty output file means the stage ran and found nothing.
//   - A missing output file means the stage never got that far.
//
// A report that treats those the same cannot distinguish a clean result from a
// crashed stage, so an empty file is never tidied away.
package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// SchemaVersion is the manifest format version.
//
// Consumers should refuse a version they do not understand rather than guess.
const SchemaVersion = 1

// Status is a stage outcome.
type Status string

const (
	// StatusSucceeded means the stage ran and its command exited zero.
	StatusSucceeded Status = "succeeded"
	// StatusFailed means the stage ran and its command did not exit zero.
	StatusFailed Status = "failed"
	// StatusSkipped means the stage did not run, and Note says why.
	StatusSkipped Status = "skipped"
)

// Stage is one recorded pipeline stage.
type Stage struct {
	Name string `json:"name"`
	// order is the stage's position in the pipeline. It is not serialised: it
	// exists so the manifest can be written in pipeline order rather than in the
	// order a concurrent pair happened to finish.
	order int `json:"-"`

	Status          Status `json:"status"`
	ExitCode        int    `json:"exit_code"`
	DurationSeconds int64  `json:"duration_seconds"`
	Inputs          int    `json:"inputs"`
	Outputs         int    `json:"outputs"`
	Note            string `json:"note"`
}

// stagesDoc is the stages.json document.
type stagesDoc struct {
	SchemaVersion        int     `json:"schema_version"`
	RunID                string  `json:"run_id"`
	Stages               []Stage `json:"stages"`
	Failed               int     `json:"failed"`
	TotalDurationSeconds int64   `json:"total_duration_seconds"`
}

// manifestDoc is the run.json document.
type manifestDoc struct {
	RunID     string   `json:"run_id"`
	Target    string   `json:"target"`
	Label     string   `json:"label"`
	Stamp     string   `json:"stamp"`
	StartedAt string   `json:"started_at"`
	EndedAt   string   `json:"ended_at,omitempty"`
	Profile   string   `json:"profile,omitempty"`
	Stages    []string `json:"stages,omitempty"`

	// The exact allowlist and denylist the run was authorised under. A result
	// is only meaningful alongside the authorization that permitted it.
	ScopeAllowlist string `json:"scope_allowlist"`
	ScopeDenylist  string `json:"scope_denylist"`
	ScopeFinger    string `json:"scope_fingerprint,omitempty"`

	DryRun       bool  `json:"dry_run"`
	AllowPrivate bool  `json:"allow_private"`
	AllowAny     bool  `json:"allow_any"`
	Elapsed      int64 `json:"elapsed_seconds"`

	ToolVersions map[string]string `json:"tool_versions,omitempty"`
}

// Run is one execution of the pipeline.
type Run struct {
	ID    string
	Dir   string
	Label string
	Stamp string

	mu      sync.Mutex
	stages  []Stage
	failed  int
	inputs  int
	started time.Time
	ended   time.Time

	// pendingNote and pendingOutputs hold what a stage reported while it was
	// running, keyed by stage name. A note is set from inside the stage
	// function, which is before its record exists, so it is held here and
	// drained when record is called. Keying by name rather than by "most
	// recent" is what makes two concurrent stages safe.
	pendingNote    map[string]string
	pendingOutputs map[string]int

	// nextSeq numbers stages in the order they were started, so the manifest
	// reads in pipeline order even though a concurrent pair is recorded in
	// completion order.
	nextSeq int

	target       string
	profile      string
	allowlist    string
	denylist     string
	dryRun       bool
	allowPrivate bool
	allowAny     bool
	toolVersions map[string]string
}

// Init prepares a run directory and returns the run.
//
// The directory is created 0700 because a run holds findings, which routinely
// include secret-shaped matches.
func Init(dir, label, stamp string) (*Run, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("run: create %s: %w", dir, err)
	}

	// MkdirAll leaves an existing directory's mode alone, so the mode is set
	// explicitly. The run directory holds findings, which routinely include
	// secret-shaped matches, so it is tightened even when it already existed.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory needs its execute bit
		return nil, fmt.Errorf("run: secure %s: %w", dir, err)
	}

	return &Run{
		ID:             stamp + "-" + label,
		Dir:            dir,
		Label:          label,
		Stamp:          stamp,
		started:        time.Now(),
		toolVersions:   map[string]string{},
		pendingNote:    map[string]string{},
		pendingOutputs: map[string]int{},
	}, nil
}

// SetTarget records what is being scanned.
func (r *Run) SetTarget(t string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.target = t
}

// SetProfile records the pacing profile.
func (r *Run) SetProfile(p string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profile = p
}

// SetScope records the exact allowlist and denylist text the run is authorized
// under.
//
// The text is stored rather than only a fingerprint, because a fingerprint says
// whether it changed but not what changed, and an auditor needs the content.
func (r *Run) SetScope(allowlist, denylist string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowlist = allowlist
	r.denylist = denylist
}

// SetDryRun records that the run contacts nothing.
func (r *Run) SetDryRun(v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dryRun = v
}

// SetAllowPrivate records the private-range override.
func (r *Run) SetAllowPrivate(v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowPrivate = v
}

// SetToolVersion records the version of an external tool.
func (r *Run) SetToolVersion(name, version string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.toolVersions[name] = version
}

// SetInputs declares the input size of the stage about to run.
func (r *Run) SetInputs(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inputs = n
}

// ErrSkip is returned by a stage that decided it does not apply to this run.
//
// A stage returns it with a reason instead of calling Skip directly. Calling
// Skip from inside a stage function would record the stage twice: once as
// skipped, and again when the runner recorded its return value.
var ErrSkip = errors.New("stage skipped")

// Stage runs fn and records its real outcome.
//
// It returns fn's error so the caller cannot accidentally continue past a
// failure. Returning ErrSkip records the stage as skipped and reports success to
// the caller, because a stage that does not apply is not a failure.
func (r *Run) Stage(name string, fn func() error) error {
	// Capture and clear the declared input size for this stage.
	r.mu.Lock()
	inputs := r.inputs
	r.inputs = 0
	r.mu.Unlock()

	start := time.Now()
	logging.Info("stage: %s", name)

	var err error
	if fn != nil {
		err = fn()
	}
	elapsed := time.Since(start)

	if errors.Is(err, ErrSkip) {
		r.mu.Lock()
		// A stage returning ErrSkip has usually already set a note saying why.
		// Carrying it onto the skipped record is the difference between
		// "targets skipped" and "targets skipped: domain mode, the roots stage
		// starts from the seeds", and the second answers the question the first
		// one raises.
		note := r.pendingNote[name]
		r.mu.Unlock()

		r.record(Stage{
			Name:            name,
			Status:          StatusSkipped,
			Note:            note,
			DurationSeconds: int64(elapsed.Seconds()),
		})
		if note != "" {
			logging.Info("stage: %s skipped (%s)", name, note)
		} else {
			logging.Info("stage: %s skipped", name)
		}
		return nil
	}

	r.record(Stage{
		Name:            name,
		Status:          statusFor(err),
		ExitCode:        exitCodeFor(err),
		DurationSeconds: int64(elapsed.Seconds()),
		Inputs:          inputs,
	})

	if err != nil {
		logging.Error("stage: %s FAILED (%s)", name, util.FormatElapsed(elapsed))
	} else {
		logging.Ok("stage: %s ok (%s)", name, util.FormatElapsed(elapsed))
	}
	return err
}

// Skip records a stage that did not run, with a reason.
func (r *Run) Skip(name, reason string) {
	logging.Info("stage: %s skipped (%s)", name, reason)
	r.record(Stage{Name: name, Status: StatusSkipped, Note: reason})
}

// SetNote attaches a note to a named stage.
//
// The stage is named rather than implied, because two stages can be running at
// once and "the stage that is currently running" is not a single thing. The note
// is held pending and drained when that stage's record is made, which is after
// its function returns, so a note can never land on its neighbour.
func (r *Run) SetNote(stage, note string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pendingNote[stage] = note
}

// RecordOutputs sets the output count for the named stage, counting only files
// that exist.
//
// An empty file counts. That is the whole point: a stage that ran and found
// nothing produced an empty file, and a stage that never ran produced nothing
// at all.
func (r *Run) RecordOutputs(stage string, paths ...string) int {
	count := 0
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			count++
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.pendingOutputs[stage] = count
	return count
}

// Stages returns the recorded stages in pipeline order.
//
// A concurrent pair finishes in whatever order it finishes, but the manifest is
// read by people and by tools that assume the stages appear as declared.
func (r *Run) Stages() []Stage {
	r.mu.Lock()
	out := make([]Stage, len(r.stages))
	copy(out, r.stages)
	r.mu.Unlock()

	sort.SliceStable(out, func(i, j int) bool { return out[i].order < out[j].order })
	return out
}

// Failed returns how many stages failed.
func (r *Run) Failed() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed
}

// Elapsed returns how long the run has been going.
func (r *Run) Elapsed() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Since(r.started)
}

// record appends a stage outcome, draining anything the stage noted while it ran.
//
// seq is the stage's start order. A backgrounded stage passes its own, because
// it is joined in completion order; an inline stage takes the next value.
func (r *Run) record(s Stage, seq ...int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	order := r.nextSeq
	if len(seq) > 0 {
		order = seq[0]
	} else {
		r.nextSeq++
	}
	s.order = order

	if note, ok := r.pendingNote[s.Name]; ok {
		s.Note = note
		delete(r.pendingNote, s.Name)
	}
	if outs, ok := r.pendingOutputs[s.Name]; ok {
		s.Outputs = outs
		delete(r.pendingOutputs, s.Name)
	}

	r.stages = append(r.stages, s)
	if s.Status == StatusFailed {
		r.failed++
	}
}

// statusFor derives a stage status from its error.
//
// ErrSkip is a stage deciding it does not apply, which is not a failure.
func statusFor(err error) Status {
	switch {
	case err == nil:
		return StatusSucceeded
	case errors.Is(err, ErrSkip):
		return StatusSkipped
	default:
		return StatusFailed
	}
}

// exitCodeFor derives a process exit code from an error.
//
// A command that exited non-zero carries its own code, which is preserved. An
// error that is not an exit-status error, such as a failure to start the tool,
// reports 1. A skipped stage reports 0, because nothing failed.
func exitCodeFor(err error) int {
	switch {
	case err == nil, errors.Is(err, ErrSkip):
		return 0
	}
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	return 1
}

// WriteStages writes stages.json.
func (r *Run) WriteStages() error {
	r.mu.Lock()
	failed := r.failed
	r.mu.Unlock()

	doc := stagesDoc{
		SchemaVersion:        SchemaVersion,
		RunID:                r.ID,
		Stages:               r.Stages(),
		Failed:               failed,
		TotalDurationSeconds: int64(time.Since(r.started).Seconds()),
	}

	return r.writeJSON("stages.json", doc)
}

// WriteManifest writes run.json.
func (r *Run) WriteManifest() error {
	r.mu.Lock()
	m := manifestDoc{
		RunID:          r.ID,
		Target:         r.target,
		Label:          r.Label,
		Stamp:          r.Stamp,
		StartedAt:      util.ISOStamp(r.started),
		Profile:        r.profile,
		ScopeAllowlist: r.allowlist,
		ScopeDenylist:  r.denylist,
		DryRun:         r.dryRun,
		AllowPrivate:   r.allowPrivate,
		AllowAny:       r.allowAny,
		Elapsed:        int64(time.Since(r.started).Seconds()),
		ToolVersions:   r.toolVersions,
	}
	if len(r.toolVersions) == 0 {
		m.ToolVersions = nil
	}
	r.mu.Unlock()

	return r.writeJSON("run.json", m)
}

// writeJSON marshals v and writes it into the run directory.
//
// The document is marshalled rather than assembled with string formatting, so a
// value containing a quote or a newline produces valid JSON instead of a file
// that no parser will read.
func (r *Run) writeJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("run: encode %s: %w", name, err)
	}
	b = append(b, '\n')

	path := filepath.Join(r.Dir, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("run: write %s: %w", path, err)
	}
	logging.Debug("run: wrote %s", path)
	return nil
}

// Finalise writes both manifests and reports whether the run is clean.
//
// It returns non-zero when any stage failed. Callers must trust this rather than
// the word "done" in the log.
func (r *Run) Finalise() error {
	r.mu.Lock()
	r.ended = time.Now()
	r.mu.Unlock()

	// The manifest is written even on failure: the failure record is the reason
	// to read it.
	if err := r.WriteManifest(); err != nil {
		return err
	}
	if err := r.WriteStages(); err != nil {
		return err
	}

	if r.Failed() > 0 {
		var names []string
		for _, s := range r.Stages() {
			if s.Status == StatusFailed {
				names = append(names, s.Name)
			}
		}
		return fmt.Errorf("run: %d stage(s) failed: %v", r.Failed(), names)
	}
	return nil
}

// SummaryLine renders a one-line human summary of the stage outcomes.
func (r *Run) SummaryLine() string {
	var okCount, failedCount, skippedCount int
	for _, s := range r.Stages() {
		switch s.Status {
		case StatusSucceeded:
			okCount++
		case StatusFailed:
			failedCount++
		case StatusSkipped:
			skippedCount++
		}
	}

	summary := fmt.Sprintf("%s: %d ok, %d failed, %d skipped in %s",
		r.Label, okCount, failedCount, skippedCount, util.FormatElapsed(r.Elapsed()))

	// Name the stages that did not do what was asked. A count alone leaves an
	// operator guessing which stage went missing, and a silently skipped stage
	// is the same failure shape as one that silently found nothing.
	if failedCount > 0 {
		summary += " (failed: " + joinComma(stagesWith(r.Stages(), StatusFailed)) + ")"
	}
	if skippedCount > 0 {
		summary += " (skipped: " + joinComma(stagesWith(r.Stages(), StatusSkipped)) + ")"
	}
	return summary
}

// stagesWith returns the names of stages in a given status.
func stagesWith(stages []Stage, want Status) []string {
	var names []string
	for _, s := range stages {
		if s.Status == want {
			names = append(names, s.Name)
		}
	}
	return names
}

// joinComma renders names for a summary suffix.
//
// An empty list yields "", because every caller appends this to a suffix that
// should disappear entirely when there is nothing to list.
func joinComma(names []string) string {
	return strings.Join(names, ", ")
}
