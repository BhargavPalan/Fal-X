package cli

import "github.com/BhargavPalan/Fal-X/internal/logging"

// The CLI reports through the logging package so that stage output, refusal
// messages, and the run manifest all share one format and one exit path.

func logWarn(msg string) { logging.Warn("%s", msg) }

func logWarnf(format string, a ...any) { logging.Warn(format, a...) }
