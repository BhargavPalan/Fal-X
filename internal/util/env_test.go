package util

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEnvFileAccepts pins the shapes a real credentials file uses.
func TestEnvFileAccepts(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")

	content := strings.Join([]string{
		"GOOD=value123",
		"export ALSO_GOOD=exported",
		"SINGLE='raw'",
		"DOUBLE=\"quoted\"",
		"DASHES=tok-123_a.b~c/d?e=f+g",
		"URL=https://api.example.com/v1?key=abc",
		"BRACKETED=[::1]:443",
		"TILDE=~/some/path",
		"# a comment",
		"   # indented comment",
		"",
		"CRLF=value\r",
	}, "\n")

	write(t, p, content)

	vars, warns, err := EnvFile(p)
	if err != nil {
		t.Fatalf("EnvFile: %v", err)
	}

	want := map[string]string{
		"GOOD":      "value123",
		"ALSO_GOOD": "exported",
		"SINGLE":    "raw",
		"DOUBLE":    "quoted",
		"DASHES":    "tok-123_a.b~c/d?e=f+g",
		"URL":       "https://api.example.com/v1?key=abc",
		"BRACKETED": "[::1]:443",
		// Tilde is an RFC 3986 unreserved character, so a path-like value is
		// permitted. Rejecting it would achieve nothing: an absolute path
		// consists entirely of permitted characters too, and no value is
		// expanded anywhere.
		"TILDE": "~/some/path",
		"CRLF":  "value",
	}
	for k, v := range want {
		got, ok := vars[k]
		if !ok {
			t.Errorf("%s missing from the parsed file", k)
			continue
		}
		if got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if len(warns) != 0 {
		t.Errorf("unexpected warnings for a well-formed file: %v", warns)
	}
}

// TestEnvFileNeverEvaluates is the critical safety property.
//
// Nothing here is executed: the parser reads bytes and returns a map. The point
// of refusing the values is that no later code path can be tricked into
// evaluating one, so the test asserts both that the value is absent and that
// the payload never ran.
func TestEnvFileNeverEvaluates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")

	canary := filepath.Join(dir, "pwned")
	payloads := []struct {
		key, line string
	}{
		{"EVIL_SUBST", "EVIL_SUBST=$(touch " + canary + "_subst)"},
		{"EVIL_BACKTICK", "EVIL_BACKTICK=`touch " + canary + "_backtick`"},
		{"EVIL_PIPE", "EVIL_PIPE=foo | touch " + canary + "_pipe"},
		{"EVIL_SEMI", "EVIL_SEMI=foo; touch " + canary + "_semi"},
		{"EVIL_AND", "EVIL_AND=foo && touch " + canary + "_and"},
		{"EVIL_REDIR", "EVIL_REDIR=foo > " + canary + "_redir"},
		{"EVIL_SPACE", "EVIL_SPACE=has space"},
		{"EVIL_MULTILINE", "EVIL_MULTILINE=\"line1\nline2\""},
		{"EVIL_DOLLAR", "EVIL_DOLLAR=${HOME}"},
		{"EVIL_BRACE", "EVIL_BRACE=${IFS}"},
		{"EVIL_BACKSLASH", "EVIL_BACKSLASH=foo\\bar"},
		{"EVIL_PAREN", "EVIL_PAREN=foo(bar)"},
		{"EVIL_GLOB", "EVIL_GLOB=*"},
		{"EVIL_BRACE_EXPAND", "EVIL_BRACE_EXPAND={a,b}"},
		{"EVIL_QUOTE_INNER", "EVIL_QUOTE_INNER=it's"},
	}

	var b strings.Builder
	for _, pl := range payloads {
		b.WriteString(pl.line)
		b.WriteString("\n")
	}
	write(t, p, b.String())

	vars, warns, err := EnvFile(p)
	if err != nil {
		t.Fatalf("EnvFile: %v", err)
	}

	for _, pl := range payloads {
		if v, ok := vars[pl.key]; ok {
			t.Errorf("%s was accepted with value %q; it must be rejected", pl.key, v)
		}
	}

	// The decisive assertion: no payload produced a file.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "pwned") {
			t.Errorf("a payload executed and created %s", e.Name())
		}
	}

	if len(warns) != len(payloads)+1 {
		// One extra: EVIL_MULTILINE contains an embedded newline, so it is read
		// as two lines and each is reported. Both halves must be rejected,
		// which is why the count is not simply len(payloads).
		t.Errorf("got %d warnings, want %d", len(warns), len(payloads)+1)
	}
}

// TestEnvFileRejectsMalformedLines pins that a broken line is reported, not
// silently accepted and not silently dropped.
func TestEnvFileRejectsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")

	content := strings.Join([]string{
		"NOEQUALS",
		"BAD KEY=nope",
		"1DIGIT=x",
		"DANGLING=\"unterminated",
		"DANGLING_SINGLE='unterminated",
		"=novalue",
		"GOOD=yes",
	}, "\n")
	write(t, p, content)

	vars, warns, err := EnvFile(p)
	if err != nil {
		t.Fatalf("EnvFile: %v", err)
	}

	if v, ok := vars["GOOD"]; !ok || v != "yes" {
		t.Error("a valid line following malformed ones was not loaded")
	}
	for _, key := range []string{"NOEQUALS", "BAD", "1DIGIT", "DANGLING", "DANGLING_SINGLE", ""} {
		if _, ok := vars[key]; ok {
			t.Errorf("malformed key %q was accepted", key)
		}
	}

	joined := warnText(warns)
	for _, want := range []string{
		"not a KEY=VALUE assignment", "invalid key", "unterminated quote",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings do not mention %q; got: %v", want, joined)
		}
	}

	// Every warning must name the line it came from, or a malformed
	// credentials file cannot be fixed.
	lineRef := regexp.MustCompile(`:\d+`)
	for _, w := range warns {
		if !lineRef.MatchString(w.Message) {
			t.Errorf("warning %q carries no line number", w.Message)
		}
	}
}

// TestEnvFileWarningsDoNotLeakValues pins that a rejected line's value is not
// repeated in the warning.
//
// A credentials file is the most sensitive input in the tree, and a warning
// that echoes the offending line would write a rejected secret into the log
// and from there into any report.
func TestEnvFileWarningsDoNotLeakValues(t *testing.T) {
	dir := t.TempDir()
	secret := "s3cr3t-value-that-must-not-be-logged"
	p := filepath.Join(dir, ".env")
	write(t, p, "TOKEN="+secret+" $(touch /tmp/x)\n")

	vars, warns, err := EnvFile(p)
	if err != nil {
		t.Fatalf("EnvFile: %v", err)
	}
	if _, ok := vars["TOKEN"]; ok {
		t.Fatal("the rejected line was accepted")
	}
	for _, w := range warns {
		if strings.Contains(w.Message, secret) {
			t.Errorf("warning leaked the credential value: %q", w.Message)
		}
	}
}

// TestEnvFileMissingFile pins the absent-file contract.
func TestEnvFileMissingFile(t *testing.T) {
	if _, _, err := EnvFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("EnvFile on a missing file returned nil error")
	}
}

// TestEnvFileCheckPerms pins that a world-readable credentials file is
// reported.
func TestEnvFileCheckPerms(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("POSIX modes are not meaningful on Windows")
	}
	dir := t.TempDir()

	tight := write(t, filepath.Join(dir, "tight"), "TOKEN=x\n")
	if err := os.Chmod(tight, 0o600); err != nil {
		t.Fatal(err)
	}
	if warns := CheckEnvFilePerms(tight); len(warns) != 0 {
		t.Errorf("a 0600 file produced warnings: %v", warns)
	}

	loose := write(t, filepath.Join(dir, "loose"), "TOKEN=x\n")
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	if warns := CheckEnvFilePerms(loose); len(warns) == 0 {
		t.Error("a 0644 credentials file produced no warning")
	}

	// An empty file holds no secrets, so its mode is not worth a warning.
	empty := write(t, filepath.Join(dir, "empty"), "")
	if err := os.Chmod(empty, 0o644); err != nil {
		t.Fatal(err)
	}
	if warns := CheckEnvFilePerms(empty); len(warns) != 0 {
		t.Errorf("an empty file produced warnings: %v", warns)
	}

	if warns := CheckEnvFilePerms(filepath.Join(dir, "absent")); len(warns) != 0 {
		t.Errorf("an absent file produced warnings: %v", warns)
	}
}

func warnText(ws []EnvWarning) string {
	var b strings.Builder
	for _, w := range ws {
		b.WriteString(w.Message)
		b.WriteString("\n")
	}
	return b.String()
}
