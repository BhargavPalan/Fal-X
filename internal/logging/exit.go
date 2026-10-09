package logging

import (
	"errors"
	"fmt"
)

// Exit statuses. See the package documentation for the contract.
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

// ErrRuntime marks an error as a runtime failure.
type ErrRuntime struct{ Err error }

func (e ErrRuntime) Error() string {
	if e.Err == nil {
		return "runtime failure"
	}
	return e.Err.Error()
}
func (e ErrRuntime) Unwrap() error { return e.Err }

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
// A command returns the failure instead of exiting from deep inside a call
// stack, so main is the only place that exits and the status contract lives in
// one spot.
func Runtimef(format string, a ...any) error {
	return ErrRuntime{Err: fmt.Errorf(format, a...)}
}

// ExitFor maps an error onto the status contract. An error that is neither a
// usage nor a scope error is a runtime failure: reporting a tool failure as a
// caller mistake would send an operator to their command line instead of the
// tool.
func ExitFor(err error) int {
	var usage ErrUsage
	var scope ErrScope
	switch {
	case err == nil:
		return StatusOK
	case errors.As(err, &usage):
		return StatusUsage
	case errors.As(err, &scope):
		return StatusScope
	default:
		return StatusRuntime
	}
}
