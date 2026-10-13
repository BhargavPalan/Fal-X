// Package logging provides leveled logging, in a text and a JSON form, and the
// exit-status contract.
//
// Status contract:
//
//	0  success
//	1  runtime failure, such as a stage or tool failing
//	2  usage or validation error, such as a bad flag or malformed input
//	3  authorization refusal (reserved: ExitFor maps an ErrScope to it, but no
//	   command emits one today)
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level orders severity. Higher is more severe.
type Level int

// The severity levels, from least to most severe.
const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	// LevelQuiet suppresses everything below error.
	LevelQuiet
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "quiet"
	}
}

// Logger writes leveled records to stdout, or stderr from warning up.
type Logger struct {
	mu     sync.Mutex
	level  Level
	json   bool
	color  bool
	stamps bool
	out    io.Writer
	errOut io.Writer
}

var std = &Logger{
	level:  LevelInfo,
	stamps: true,
	out:    os.Stdout,
	errOut: os.Stderr,
}

// SetLevel sets the threshold. Records below it are discarded.
func SetLevel(l Level) { std.mu.Lock(); std.level = l; std.mu.Unlock() }

// SetJSON switches between the text and JSON forms.
func SetJSON(v bool) { std.mu.Lock(); std.json = v; std.mu.Unlock() }

// SetColor enables ANSI colour on the text form.
func SetColor(v bool) { std.mu.Lock(); std.color = v; std.mu.Unlock() }

// SetTimestamps controls whether the text form prefixes a timestamp.
func SetTimestamps(v bool) { std.mu.Lock(); std.stamps = v; std.mu.Unlock() }

// SetOutputs redirects stdout and stderr, so tests can capture output.
func SetOutputs(out, errOut io.Writer) {
	std.mu.Lock()
	std.out, std.errOut = out, errOut
	std.mu.Unlock()
}

func colorize(code, s string, enabled bool) string {
	if !enabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (lg *Logger) write(l Level, tag, color, msg string) {
	lg.mu.Lock()
	defer lg.mu.Unlock()
	if l < lg.level || lg.level == LevelQuiet && l < LevelError {
		return
	}

	sink := lg.out
	if l >= LevelWarn {
		sink = lg.errOut
	}
	if sink == nil {
		return
	}

	if lg.json {
		rec := map[string]any{
			"ts":    time.Now().UTC().Format(time.RFC3339),
			"level": l.String(),
			"msg":   msg,
		}
		if b, err := json.Marshal(rec); err == nil {
			fmt.Fprintln(sink, string(b))
			return
		}
	}

	stamp := ""
	if lg.stamps {
		stamp = time.Now().Format("15:04:05 ")
	}
	fmt.Fprintf(sink, "%s%s %s\n", stamp, colorize(color, tag, lg.color), msg)
}

// Debug logs at debug level.
func Debug(format string, a ...any) { std.write(LevelDebug, "[.]", "0;90", fmt.Sprintf(format, a...)) }

// Info logs at info level.
func Info(format string, a ...any) { std.write(LevelInfo, "[*]", "0;36", fmt.Sprintf(format, a...)) }

// Ok logs a success line: info with a success marker.
func Ok(format string, a ...any) { std.write(LevelInfo, "[+]", "0;32", fmt.Sprintf(format, a...)) }

// Warn logs a warning: a condition that needs attention but does not stop the run.
func Warn(format string, a ...any) { std.write(LevelWarn, "[!]", "0;33", fmt.Sprintf(format, a...)) }

// Error logs an error.
func Error(format string, a ...any) { std.write(LevelError, "[x]", "0;31", fmt.Sprintf(format, a...)) }
