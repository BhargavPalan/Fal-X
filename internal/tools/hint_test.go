package tools

import (
	"strings"
	"testing"
)

// TestInstallHintNamesTheCommand checks that the hint points at the built-in
// install command, which is the same on every platform. The message is read by
// someone whose run just skipped a stage, so it must name something runnable.
func TestInstallHintNamesTheCommand(t *testing.T) {
	hint := InstallHint()
	if !strings.Contains(hint, "fal-x install") {
		t.Errorf("install hint should name 'fal-x install', got %q", hint)
	}
	for _, bad := range []string{"sudo", "bash", "install.sh", "install.ps1"} {
		if strings.Contains(hint, bad) {
			t.Errorf("install hint should not mention %q, got %q", bad, hint)
		}
	}
}
