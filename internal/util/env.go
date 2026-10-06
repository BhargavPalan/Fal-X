package util

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// EnvWarning is one rejected or notable line from a credential file.
//
// Message never contains the offending line's value. A credentials file is the
// most sensitive input in the tree, and echoing a rejected secret into the log
// would copy it into every report produced afterwards.
type EnvWarning struct {
	Line    int
	Message string
}

// valueRunes is the set of characters a value may contain.
//
// This is the RFC 3986 unreserved and reserved sets plus space. It covers API
// tokens, URLs and bracketed IPv6 literals, and excludes every shell
// metacharacter: $ ` | ; & < > ( ) { } newline and backslash.
//
// Nothing here is ever evaluated, so refusing a payload is not about preventing
// execution at this point. It is so that no later code path can be handed one,
// and so that a value read from disk cannot become one.
const valueRunes = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"abcdefghijklmnopqrstuvwxyz" +
	"0123456789" +
	"._~:/?#[]@!+,%=-"

// envLineMax bounds a single line in a credentials file. A credential can be a
// long token, so the ceiling is generous, but it exists so that a file with a
// pathological line is reported rather than silently truncated.
const envLineMax = 1024 * 1024

// EnvFile parses a credentials file as data and returns its assignments.
//
// The file is never evaluated. Only these forms are accepted:
//
//	KEY=value
//	export KEY=value
//	KEY="value"
//	KEY='value'
//
// A key must match [A-Za-z_][A-Za-z0-9_]*. Comments and blank lines are
// ignored. Any other line is reported in the returned warnings and skipped.
//
// Values are returned rather than pushed into the process environment, so
// parsing has no side effect and is safe to call from a test.
func EnvFile(path string) (map[string]string, []EnvWarning, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("util: read credentials: %w", err)
	}
	defer f.Close()

	vars := make(map[string]string)
	var warns []EnvWarning

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, lineScannerInitial), envLineMax)

	for lineno := 1; sc.Scan(); lineno++ {
		line := strings.TrimRight(sc.Text(), "\r")
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// An optional export prefix.
		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && isSpace(rest[0]) {
			line = strings.TrimSpace(rest)
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			warns = append(warns, warnAt(path, lineno, "not a KEY=VALUE assignment, skipped"))
			continue
		}

		key = strings.TrimSpace(key)
		if !validEnvKey(key) {
			warns = append(warns, warnAt(path, lineno, "invalid key, skipped"))
			continue
		}

		value = strings.TrimSpace(value)
		value, ok = unwrapQuotes(value)
		if !ok {
			warns = append(warns, warnAt(path, lineno, "unterminated quote, skipped"))
			continue
		}

		if !validEnvValue(value) {
			warns = append(warns, warnAt(path, lineno, "value contains disallowed characters, skipped"))
			continue
		}

		vars[key] = value
	}

	if err := sc.Err(); err != nil {
		return nil, warns, fmt.Errorf("util: read credentials: %w", err)
	}
	return vars, warns, nil
}

// warnAt builds a warning that names the file and line it came from.
//
// The location goes in the message rather than only the Line field because the
// warning is printed to a log, where a bare line number is not enough to find
// the problem in the file.
//
// The line's value is never included, whatever it contained.
func warnAt(path string, line int, msg string) EnvWarning {
	return EnvWarning{Line: line, Message: fmt.Sprintf("%s:%d: %s", path, line, msg)}
}

// validEnvKey reports whether key matches [A-Za-z_][A-Za-z0-9_]*.
func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case c >= '0' && c <= '9':
			// A digit may not be the first character.
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// unwrapQuotes removes exactly one layer of matching quotes.
//
// An opening quote with no closing partner is a malformed line, not a value,
// so it reports false rather than returning the quoted text as-is.
func unwrapQuotes(v string) (string, bool) {
	if len(v) < 2 {
		return v, true
	}
	switch v[0] {
	case '"':
		if strings.HasSuffix(v, `"`) && len(v) >= 2 {
			return v[1 : len(v)-1], true
		}
		return "", false
	case '\'':
		if strings.HasSuffix(v, `'`) && len(v) >= 2 {
			return v[1 : len(v)-1], true
		}
		return "", false
	}
	return v, true
}

// validEnvValue reports whether every rune of v is permitted.
func validEnvValue(v string) bool {
	for _, r := range v {
		if r > 0x7f || !strings.ContainsRune(valueRunes, r) {
			return false
		}
	}
	return true
}

// isSpace reports whether c is horizontal whitespace.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t'
}

// CheckEnvFilePerms reports whether a non-empty credentials file is readable by
// anyone but its owner.
//
// Advisory rather than fatal: a file on a mounted volume can carry an
// unavoidable mode, and refusing to run would be worse than saying so.
func CheckEnvFilePerms(path string) []EnvWarning {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return nil
	}
	// A file holding no assignment holds no secret, so its mode is not worth a
	// warning. Size is the wrong test for that: the template is all comments, so
	// an untouched copy is thousands of bytes of nothing. Warning about it on
	// every run trains the operator to ignore the warning that matters.
	if !fileHoldsAValue(path) {
		return nil
	}

	mode := fi.Mode().Perm()
	if mode&0o077 == 0 {
		return nil
	}
	return []EnvWarning{{
		Line: 0,
		Message: fmt.Sprintf("%s is mode %04o; credentials should be 0600 (chmod 600 %s)",
			path, mode, path),
	}}
}

// fileHoldsAValue reports whether path assigns anything. Comments and blank
// lines do not count.
func fileHoldsAValue(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, lineScannerInitial), envLineMax)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok &&
			strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}
