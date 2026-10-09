//go:build windows

package tools

import "os/exec"

// configureProcessGroup is a no-op on Windows, where there is no process group
// to signal the way there is on Unix.
//
// Cancellation still works: exec.CommandContext kills the direct child, and
// Exec.Run's WaitDelay bounds how long Wait blocks on inherited pipe handles. A
// detached helper a tool spawns may be left running.
func configureProcessGroup(*exec.Cmd) {}
