package logging

import "os/exec"

// lookPath is split out so tests can stub tool detection.
var lookPath = exec.LookPath
