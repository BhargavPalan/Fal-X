package tools

// InstallHint is the command that installs the external tools. It is built into
// the binary and works the same on every platform, so there is no OS-specific
// phrasing to get wrong.
func InstallHint() string {
	return "fal-x install"
}
