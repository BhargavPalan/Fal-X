package logging

import (
	"errors"
	"fmt"
	"os"
)

// Exit statuses. See package documentation for the contract.
const (
	// StatusOK is a successful run.
	StatusOK = 0
	// StatusRuntime is a runtime failure such as a stage or tool failing.
	StatusRuntime = 1
	// StatusUsage is a usage or validation error.
	StatusUsage = 2
	// StatusScope is an authorization or scope refusal.
	StatusScope = 3
	// StatusInterrupted is a signal-terminated run.
	StatusInterrupted = 130
)

// exitFn is indirected so tests can capture the status instead of exiting.
var exitFn = os.Exit

// SetExitFunc replaces the exit function. Tests use it to assert on status.
func SetExitFunc(fn func(int)) { exitFn = fn }

// ErrUsage marks an error as a usage or validation failure.
type ErrUsage struct{ Err error }

func (e ErrUsage) Error() string {
	if e.Err == nil {
		return "invalid usage"
	}
	return e.Err.Error()
}
func (e ErrUsage) Unwrap() error { return e.Err }

// ErrScope marks an error as an authorization or scope refusal.
type ErrScope struct{ Err error }

func (e ErrScope) Error() string {
	if e.Err == nil {
		return "authorization required"
	}
	return e.Err.Error()
}
func (e ErrScope) Unwrap() error { return e.Err }

// Usagef builds a usage error.
func Usagef(format string, a ...any) error {
	return ErrUsage{Err: fmt.Errorf(format, a...)}
}

// Scopef builds a scope refusal error.
func Scopef(format string, a ...any) error {
	return ErrScope{Err: fmt.Errorf(format, a...)}
}

// Runtimef builds a runtime failure error.
//
// This exists so a command can return the failure instead of calling Fatal and
// exiting from deep inside a call stack. main is the only place that exits,
// which keeps the status contract in one place.
func Runtimef(format string, a ...any) error {
	return ErrRuntime{Err: fmt.Errorf(format, a...)}
}

// ErrRuntime marks an error as a runtime failure.
type ErrRuntime struct{ Err error }

func (e ErrRuntime) Error() string {
	if e.Err == nil {
		return "runtime failure"
	}
	return e.Err.Error()
}
func (e ErrRuntime) Unwrap() error { return e.Err }

// Refusal classifies a failure into the three-way split the status contract
// describes.
//
// It lives here rather than in each package that can refuse, because a second
// representation of the same split is one more thing to keep in step, and the
// status a caller sees must not depend on which layer produced the error.
type Refusal int

const (
	// RefuseNone means no refusal.
	RefuseNone Refusal = iota
	// RefuseUsage is a bad flag, malformed input, or contradictory modes.
	RefuseUsage
	// RefuseScope is an authorization or scope refusal.
	RefuseScope
)

func (r Refusal) String() string {
	switch r {
	case RefuseUsage:
		return "usage"
	case RefuseScope:
		return "scope"
	default:
		return "runtime"
	}
}

// RefusalOf classifies err.
//
// An unclassified error is a runtime failure rather than a usage error. The
// default has to be the conservative one: reporting a tool failure as a caller
// mistake would send an operator looking at their command line instead of at the
// tool.
func RefusalOf(err error) Refusal {
	if err == nil {
		return RefuseNone
	}
	var usage ErrUsage
	if errors.As(err, &usage) {
		return RefuseUsage
	}
	var scopeErr ErrScope
	if errors.As(err, &scopeErr) {
		return RefuseScope
	}
	return RefuseNone
}

// ExitFor maps an error onto the status contract.
func ExitFor(err error) int {
	if err == nil {
		return StatusOK
	}
	var usage ErrUsage
	if errors.As(err, &usage) {
		return StatusUsage
	}
	var scope ErrScope
	if errors.As(err, &scope) {
		return StatusScope
	}
	return StatusRuntime
}

// Fatal reports a message and exits with a runtime failure status.
func Fatal(format string, a ...any) {
	Error(format, a...)
	exitFn(StatusRuntime)
}

// FatalUsage reports a message and exits with a usage status.
func FatalUsage(format string, a ...any) {
	Error(format, a...)
	exitFn(StatusUsage)
}

// FatalScope reports a message and exits with a scope refusal status.
func FatalScope(format string, a ...any) {
	Error(format, a...)
	exitFn(StatusScope)
}

// FatalErr reports err and exits with the status the error maps to.
func FatalErr(err error) {
	if err == nil {
		return
	}
	Error("%v", err)
	exitFn(ExitFor(err))
}
