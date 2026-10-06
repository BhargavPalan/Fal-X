//go:build !windows

package tools

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the child in its own process group and makes
// cancellation kill the whole group.
//
// This matters for two reasons. exec.CommandContext kills only the direct child,
// so a tool that shells out to a helper would leave that helper running. And
// because a grandchild inherits the write end of the output pipe, cmd.Wait would
// block until it finished on its own, which is how an interrupted run appears to
// hang until the tool's own timeout expires.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// The negative pid targets the whole group.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			// Fall back to the single process if the group is already gone.
			return cmd.Process.Kill()
		}
		return nil
	}
}
