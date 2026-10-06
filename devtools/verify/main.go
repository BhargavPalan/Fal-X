// Command verify is the verification gate.
//
// Everything it checks must pass before a change is reported as done. The checks
// are deliberately separate: a gate that runs them together hides which one broke,
// and "tests pass" says nothing about whether the tree is even valid Go.
//
//  1. gofmt       formatting is canonical
//  2. go vet      suspicious constructs
//  3. go build    it compiles
//  4. go test     the suite passes
//
// Integration tests need a Postgres database. Set FALX_TEST_DSN to run them;
// without it they skip, and the skip is reported rather than hidden.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n\033[31mFAIL\033[0m %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n\033[32mall checks passed\033[0m\n")
}

func run() error {
	steps := []struct {
		name string
		desc string
		fn   func() error
	}{
		{"gofmt", "formatting is canonical", checkFmt},
		{"go vet", "vet is clean", checkVet},
		{"go build", "build succeeds", checkBuild},
		{"go test", "tests pass", checkTest},
	}

	for _, s := range steps {
		fmt.Printf("\n\033[2m%s\033[0m\n", s.name)
		if err := s.fn(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		fmt.Printf("\033[32mok\033[0m   %s\n", s.desc)
	}
	return nil
}

// out runs a command and returns its combined output.
func out(name string, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return strings.TrimRight(buf.String(), "\n"), err
}

// checkFmt fails when any file is not canonically formatted.
func checkFmt() error {
	files, err := out("gofmt", "-l", "cmd", "internal", "devtools")
	if err != nil {
		return err
	}
	if files != "" {
		return fmt.Errorf("these files are not formatted, run: make fmt\n%s", files)
	}
	return nil
}

func checkVet() error   { return report("go", "vet", "./...") }
func checkBuild() error { return report("go", "build", "./...") }

// checkTest runs the suite, reporting whether integration tests were enabled.
func checkTest() error {
	if os.Getenv("FALX_TEST_DSN") == "" {
		fmt.Printf("\033[33mno FALX_TEST_DSN, integration tests will skip\033[0m\n")
	}
	return report("go", "test", "-count=1", "./...")
}

// report runs a command and folds its output into an error.
func report(name string, args ...string) error {
	o, err := out(name, args...)
	if o != "" {
		fmt.Println(o)
	}
	return err
}
