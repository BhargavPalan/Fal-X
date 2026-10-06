package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/logging"
)

// runSubcommand dispatches to a subcommand by name.
func runSubcommand(t *testing.T, name string, args []string) error {
	t.Helper()
	for _, c := range commands {
		if c.name == name {
			return c.run(context.Background(), args)
		}
	}
	t.Fatalf("no subcommand named %q", name)
	return nil
}

// TestSubcommandHelpIsNotAFailure pins that asking a subcommand for help does not
// count as a failure.
//
// The flag package rejects an undeclared --help as an undefined flag, so
// "fal-x scan --help" exited 2 with an error rather than printing anything. A
// caller checking the exit status would read a request for documentation as a
// usage mistake.
//
// The subcommand returns the errHelp sentinel and main maps that to exit 0.
// Asserting the sentinel rather than nil is what pins that mapping: the
// sentinel has to survive the return, or the status becomes 1.
func TestSubcommandHelpIsNotAFailure(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		args []string
	}{
		{"scan --help", "scan", []string{"--help"}},
		{"scan -h", "scan", []string{"-h"}},
		{"migrate --help", "migrate", []string{"--help"}},
		{"migrate -h", "migrate", []string{"-h"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runSubcommand(t, tc.cmd, tc.args)

			if !errors.Is(err, errHelp) {
				t.Fatalf("%q returned %v, want errHelp", tc.name, err)
			}
			// exitCode is what main actually uses, so this is the status a
			// caller observes. A help request that printed the flags and then
			// exited non-zero would still be a bug.
			if got := exitCode(err); got != 0 {
				t.Errorf("exitCode = %d, want 0 for a help request", got)
			}
		})
	}
}

// TestHelpStopsBeforeAnyWork pins that --help does not also run the command.
// Help output that also starts a scan would be worse than no help at all.
func TestHelpStopsBeforeAnyWork(t *testing.T) {
	// No target, no scope, no authorization: without the help short-circuit this
	// would fail with a usage or scope refusal rather than errHelp.
	err := runSubcommand(t, "scan", []string{"--help"})
	if !errors.Is(err, errHelp) {
		t.Errorf("scan --help = %v, want errHelp; the command ran despite being asked for help", err)
	}
}

// TestUnknownFlagIsStillAUsageError guards the other half: making --help work
// must not make an unrecognised flag succeed.
func TestUnknownFlagIsStillAUsageError(t *testing.T) {
	probe := flagSet("scan")
	err := parseFlags(probe, "fal-x scan ...", []string{"--nonsense"})

	if err == nil {
		t.Fatal("an unknown flag was accepted")
	}
	if logging.RefusalOf(err) != logging.RefuseUsage {
		t.Errorf("refusal = %v, want %v", logging.RefusalOf(err), logging.RefuseUsage)
	}
	if logging.ExitFor(err) != 2 {
		t.Errorf("status = %d, want 2", logging.ExitFor(err))
	}
}

// TestEverySubcommandIsDispatchable pins that every advertised subcommand is
// actually wired up. The help text is generated from the same table, so a
// command that is listed but not registered would only fail at run time.
func TestEverySubcommandIsDispatchable(t *testing.T) {
	for _, c := range commands {
		if c.run == nil {
			t.Errorf("subcommand %q has no implementation", c.name)
		}
	}
}

// TestExitCodeClassifiesEveryOutcome pins the whole status table in one place.
//
// Each row is the documented contract: 0 success, 1 runtime failure, 2 usage,
// 3 authorization refusal, 130 signal.
func TestExitCodeClassifiesEveryOutcome(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, 0},
		{"help", errHelp, 0},
		{"wrapped help", fmt.Errorf("x: %w", errHelp), 0},
		{"interrupted", context.Canceled, 130},
		{"runtime failure", errors.New("boom"), 1},
		{"usage", logging.Usagef("bad flag"), 2},
		{"scope refusal", logging.Scopef("no allowlist"), 3},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCode(tc.err); got != tc.want {
				t.Errorf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}
