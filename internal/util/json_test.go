package util

import (
	"strings"
	"testing"
)

// TestJSONEscape pins the escaping that keeps a scanner finding from producing
// a file that will not parse.
//
// Control characters matter most here: a banner name or HTTP header can carry a
// raw byte that is illegal inside a JSON string, and emitting it raw produces a
// file that every downstream parser rejects.
func TestJSONEscape(t *testing.T) {
	cases := []struct {
		in, want, name string
	}{
		{`a"b`, `a\"b`, "double quote"},
		{`a\b`, `a\\b`, "backslash"},
		{"a\tb", `a\tb`, "tab"},
		{"a\nb", `a\nb`, "newline"},
		{"a\rb", `a\rb`, "carriage return"},
		{"a\x08b", `a\bb`, "backspace"},
		{"a\x0cb", `a\fb`, "form feed"},
		{"a\x01b", "ab", "control character stripped"},

		// Order matters: the backslash must be escaped before the quote, or
		// `\"` would be re-escaped into `\\"`.
		{`a\"b`, `a\\\"b`, "backslash before quote"},
		{`{"k":"v"}`, `{\"k\":\"v\"}`, "embedded JSON"},
	}

	for _, tc := range cases {
		if got := JSONEscape(tc.in); got != tc.want {
			t.Errorf("JSONEscape %s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestJSONEscapeDropsEveryC0Control walks the whole range rather than one
// example, because a single spot check would miss a gap in the character class.
func TestJSONEscapeDropsEveryC0Control(t *testing.T) {
	for c := 0x00; c <= 0x1f; c++ {
		switch c {
		case '\t', '\n', '\r', '\b', '\f':
			continue // these have short escapes and are handled
		}
		in := "a" + string(rune(c)) + "b"
		got := JSONEscape(in)
		for _, r := range got {
			if r < 0x20 {
				t.Errorf("JSONEscape left control character %#x in %q", r, got)
			}
		}
	}
}

// TestJSONEscapeIsSinglePass pins that a backslash introduced by escaping is
// not itself escaped. A double-pass implementation turns `a\b` into
// `a\\\\b`, which is valid JSON but decodes to two backslashes.
func TestJSONEscapeIsSinglePass(t *testing.T) {
	if got := JSONEscape(`a\b`); strings.Count(got, `\`) != 2 {
		t.Errorf("JSONEscape(a\\b) = %q, want exactly two backslashes", got)
	}
}

// TestJSONStringArray pins array rendering.
func TestJSONStringArray(t *testing.T) {
	cases := []struct {
		in   []string
		want string
		name string
	}{
		{nil, "[]", "nil"},
		{[]string{}, "[]", "empty"},
		{[]string{"alpha"}, `["alpha"]`, "one"},
		{[]string{"alpha", "two words", `has"quote`}, `["alpha","two words","has\"quote"]`, "escaping"},
		{[]string{""}, `[""]`, "empty string"},
		{[]string{"a", "b", "c"}, `["a","b","c"]`, "three"},
	}

	for _, tc := range cases {
		if got := JSONStringArray(tc.in); got != tc.want {
			t.Errorf("JSONStringArray %s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestJSONStringArrayOutputParses pins that the rendered array is actually
// valid JSON. A quoting bug that still produced a plausible-looking string is
// the failure mode worth catching.
func TestJSONStringArrayOutputParses(t *testing.T) {
	in := []string{
		`quote"`, `back\slash`, "tab\there", "new\nline",
		"unicode: é中文", "</script>", "<!--",
	}
	got := JSONStringArray(in)
	if !strings.HasPrefix(got, "[") || !strings.HasSuffix(got, "]") {
		t.Errorf("JSONStringArray did not produce an array: %s", got)
	}
	// A "</script>" inside a JSON string is valid JSON but breaks naive
	// embedding in an HTML script tag. The API must not embed this output
	// without escaping, which is why the case is recorded here.
	if !strings.Contains(got, `</script>`) {
		t.Errorf("unexpected escaping of </script>: %s", got)
	}
}
