package util

import (
	"io"
	"strings"
)

// JSONEscape escapes s for embedding inside a JSON string.
//
// The escape pass is a single ordered walk rather than a chain of
// replacements, so a backslash introduced by escaping is not itself escaped.
//
// Control characters with no short form are dropped. They are illegal inside a
// JSON string, and a banner name or header can carry one, which would produce a
// file that every downstream parser rejects.
func JSONEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)

	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				// No short escape; drop it rather than emit invalid JSON.
				continue
			}
			b.WriteRune(r)
		}
	}

	return b.String()
}

// JSONStringArray renders values as a JSON array of strings.
func JSONStringArray(values []string) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, v := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(JSONEscape(v))
		b.WriteByte('"')
	}
	b.WriteByte(']')
	return b.String()
}

// copyBuffered copies src into dst in fixed-size chunks.
//
// io.Copy would do, but routing every hash through one helper keeps the buffer
// policy in a single place.
func copyBuffered(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	return io.CopyBuffer(dst, src, buf)
}
