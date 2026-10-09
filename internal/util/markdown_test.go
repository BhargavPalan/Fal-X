package util

import (
	"strings"
	"testing"
)

func TestMarkdownTextNeutralisesMarkup(t *testing.T) {
	cases := map[string]string{
		"plain text":                        "plain text",
		"a | b":                             "a \\| b",
		"<script>x</script>":                "&lt;script&gt;x&lt;/script&gt;",
		"[click](http://evil.example)":      "\\[click\\]\\(http://evil.example\\)",
		"`code` and *bold* and _em_":        "\\`code\\` and \\*bold\\* and \\_em\\_",
		"line one\nline two\r\nline three":  "line one line two line three",
		"a \\ backslash":                    "a \\\\ backslash",
		"fish & chips":                      "fish &amp; chips",
		"![img](http://evil.example/x.png)": "\\!\\[img\\]\\(http://evil.example/x.png\\)",
		"# heading":                         "\\# heading",
	}
	for in, want := range cases {
		if got := MarkdownText(in); got != want {
			t.Errorf("MarkdownText(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMarkdownTextLeavesNoLiveLinkOrTag pins the property that matters rather
// than each escape: whatever the input, the output contains no unescaped
// character that could open a link, image, tag or code span.
func TestMarkdownTextLeavesNoLiveLinkOrTag(t *testing.T) {
	hostile := "<img src=x onerror=1> [a](b) ![c](d) `e` *f* _g_ | \\ &amp;"
	out := MarkdownText(hostile)
	for _, bad := range []byte{'<', '>', '[', ']', '`', '*', '_', '|'} {
		for i := 0; i < len(out); i++ {
			if out[i] == bad && (i == 0 || out[i-1] != '\\') {
				t.Fatalf("unescaped %q at %d in %q", bad, i, out)
			}
		}
	}
	if strings.ContainsAny(out, "\r\n") {
		t.Error("a line break survived, which would end a table row")
	}
}
