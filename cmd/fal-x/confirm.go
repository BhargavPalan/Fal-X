package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/cli"
	"github.com/BhargavPalan/Fal-X/internal/logging"
)

// stdinIsTerminal reports whether standard input is an interactive terminal.
//
// It matters because a confirmation prompt cannot be answered by a pipeline, a
// cron job, or a CI step. Those callers must state the answer on the command
// line instead, and silently defaulting either way would be the wrong default.
func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// confirmWideTarget asks the operator to accept a target whose reach is wider
// than its name suggests.
//
// interactive says whether there is somebody there to ask. Without a terminal
// the answer has to come from --yes, because defaulting to "yes" for a bulk
// target is the one option that cannot be undone.
func confirmWideTarget(needs *cli.NeedsConfirm, interactive bool) (bool, error) {
	if !interactive {
		fmt.Fprintf(os.Stderr, "%s\n\n", needs.Prompt)
		return false, logging.Usagef(
			"standard input is not a terminal, so this cannot be confirmed interactively.\n" +
				"Re-run with --yes once you have checked the range.")
	}

	fmt.Fprintf(os.Stderr, "%s\n\n", needs.Prompt)

	reader := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stderr, "Proceed? [y/N] ")

	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		// EOF with no answer is a refusal, not consent.
		fmt.Fprintln(os.Stderr)
		return false, nil
	}

	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
