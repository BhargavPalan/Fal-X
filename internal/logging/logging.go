// Package logging provides leveled, structured logging with a text and a JSON
// form, plus the exit helpers that implement Fal-X's status contract.
//
// Status contract:
//
//	0  success
//	1  runtime failure, such as a stage or tool failing
//	2  usage or validation error, such as a bad flag or malformed input
//	3  authorization or scope refusal
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
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

// ParseLevel maps a name to a Level. Unknown names fall back to info.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "quiet":
		return LevelQuiet
	default:
		return LevelInfo
	}
}

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

// Logger writes leveled records to one or more sinks.
type Logger struct {
	mu     sync.Mutex
	level  Level
	json   bool
	color  bool
	stamps bool
	out    io.Writer
	errOut io.Writer
	extra  []io.Writer
}

var std = &Logger{
	level:  LevelInfo,
	color:  false,
	stamps: true,
	out:    os.Stdout,
	errOut: os.Stderr,
}

// Default returns the process logger.
func Default() *Logger { return std }

// SetLevel sets the threshold. Records below it are discarded.
func SetLevel(l Level) { std.mu.Lock(); std.level = l; std.mu.Unlock() }

// CurrentLevel reports the current threshold.
func CurrentLevel() Level { std.mu.Lock(); defer std.mu.Unlock(); return std.level }

// SetJSON switches between the text and JSON forms.
func SetJSON(v bool) { std.mu.Lock(); std.json = v; std.mu.Unlock() }

// SetColor enables ANSI colour on the text form.
func SetColor(v bool) { std.mu.Lock(); std.color = v; std.mu.Unlock() }

// SetTimestamps controls whether the text form prefixes a timestamp.
func SetTimestamps(v bool) { std.mu.Lock(); std.stamps = v; std.mu.Unlock() }

// SetOutputs redirects stdout and stderr. Used by tests to capture output.
func SetOutputs(out, errOut io.Writer) {
	std.mu.Lock()
	std.out, std.errOut = out, errOut
	std.mu.Unlock()
}

// Tee adds a sink that receives every record at or above the threshold. Used to
// mirror the human log into a run directory.
func Tee(w io.Writer) {
	std.mu.Lock()
	std.extra = append(std.extra, w)
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

	sinks := append([]io.Writer{lg.out}, lg.extra...)
	if l >= LevelWarn {
		sinks = append([]io.Writer{lg.errOut}, lg.extra...)
	}

	stamp := ""
	if lg.stamps {
		stamp = time.Now().Format("15:04:05 ")
	}

	for _, sink := range sinks {
		if sink == nil {
			continue
		}
		if lg.json {
			rec := map[string]any{
				"ts":    time.Now().UTC().Format(time.RFC3339),
				"level": l.String(),
				"msg":   msg,
			}
			if b, err := json.Marshal(rec); err == nil {
				fmt.Fprintln(sink, string(b))
				continue
			}
		}
		fmt.Fprintf(sink, "%s%s %s\n", stamp, colorize(color, tag, lg.color), msg)
	}
}

// Debug logs at debug level.
func Debug(format string, a ...any) { std.write(LevelDebug, "[.]", "0;90", fmt.Sprintf(format, a...)) }

// Info logs at info level.
func Info(format string, a ...any) { std.write(LevelInfo, "[*]", "0;36", fmt.Sprintf(format, a...)) }

// Ok logs a success line. Semantically info with a success marker.
func Ok(format string, a ...any) { std.write(LevelInfo, "[+]", "0;32", fmt.Sprintf(format, a...)) }

// Warn logs a warning. These are expected conditions that need attention.
func Warn(format string, a ...any) { std.write(LevelWarn, "[!]", "0;33", fmt.Sprintf(format, a...)) }

// Error logs an error.
func Error(format string, a ...any) { std.write(LevelError, "[x]", "0;31", fmt.Sprintf(format, a...)) }

// Have reports whether a tool is on PATH.
func Have(tool string) bool {
	_, err := lookPath(tool)
	return err == nil
}

// HaveAll reports whether every named tool is on PATH.
func HaveAll(tools ...string) bool {
	for _, t := range tools {
		if !Have(t) {
			return false
		}
	}
	return true
}

// Missing returns the tools that are not on PATH.
func Missing(tools ...string) []string {
	var out []string
	for _, t := range tools {
		if !Have(t) {
			out = append(out, t)
		}
	}
	return out
}
