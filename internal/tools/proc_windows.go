//go:build windows

package tools

import "os/exec"

// configureProcessGroup is a no-op on Windows, where there is no process group
// to signal the way there is on Unix.
//
// Cancellation still works: exec.CommandContext kills the direct child, and
// WaitDelay below bounds how long Wait blocks on inherited pipe handles. A tool
// that spawns a detached helper on Windows may leave it running, which is a
// platform limitation rather than something this package can fix here.
func configureProcessGroup(cmd *exec.Cmd) {}
