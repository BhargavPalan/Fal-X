package run

import (
	"fmt"
	"sync"
	"time"
)

// StageHandle is a backgrounded stage.
//
// The record is made by the parent when Wait is called, not from inside the
// goroutine. A goroutine updating the shared stage list from within itself would
// race, and worse, a stage that finished would sometimes be missing from the
// manifest entirely.
//
// seq is the order the stage was started in. Recording happens in join order,
// which for a concurrent pair is completion order, so the manifest would read
// out of pipeline order. seq restores it.
type StageHandle struct {
	owner *Run
	name  string
	seq   int
	done  chan struct{}

	mu   sync.Mutex
	err  error
	dur  int64
	ins  int
	code int
}

// StageAsync starts fn in the background and returns a handle to join it.
//
// The two real concurrent pairs in the pipeline are ports|http and content|scan.
// Neither may assume the other's output exists.
func (r *Run) StageAsync(name string, fn func() error) (*StageHandle, error) {
	r.mu.Lock()
	ins := r.inputs
	r.inputs = 0
	seq := r.nextSeq
	r.nextSeq++
	r.mu.Unlock()

	h := &StageHandle{owner: r, name: name, seq: seq, done: make(chan struct{})}

	go func() {
		defer close(h.done)

		// A panicking tool is a failed stage, not a crashed run. Without this
		// the manifest would be lost exactly when it matters most.
		defer func() {
			if rec := recover(); rec != nil {
				h.mu.Lock()
				h.err = fmt.Errorf("stage %s panicked: %v", name, rec)
				h.code = 1
				h.mu.Unlock()
			}
		}()

		start := time.Now()
		err := fn()
		dur := time.Since(start)

		h.mu.Lock()
		h.err = err
		h.dur = int64(dur.Seconds())
		h.ins = ins
		h.code = exitCodeFor(err)
		h.mu.Unlock()
	}()

	return h, nil
}

// Wait blocks until the stage finishes, records its outcome, and returns the
// stage's error.
//
// The record is made here, in the parent, which is the only place the shared
// stage list can be safely updated. A stage that returned ErrSkip is recorded as
// skipped and reports success, matching Stage.
func (h *StageHandle) Wait() error {
	<-h.done

	h.mu.Lock()
	err, dur, ins := h.err, h.dur, h.ins
	h.mu.Unlock()

	h.owner.record(Stage{
		Name:            h.name,
		Status:          statusFor(err),
		ExitCode:        exitCodeFor(err),
		DurationSeconds: dur,
		Inputs:          ins,
	}, h.seq)

	return err
}
