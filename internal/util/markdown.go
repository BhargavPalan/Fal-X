package util

import "strings"

// MarkdownText makes untrusted text safe to place in a Markdown document.
//
// Page titles, banners, hostnames and URLs come from scanned hosts, so they are
// data and must never become markup: a title of "[click](http://evil)" would
// otherwise render as a live link in a report someone is about to be handed. Every
// character that can open a link, image, tag, code span, emphasis, heading or
// table cell is escaped, and line breaks become spaces so a value cannot end a
// table row. The result renders as exactly the text that was given.
func MarkdownText(s string) string {
	s = strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ").Replace(s)
	var b strings.Builder
	b.Grow(len(s) + len(s)/8)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '\\', '`', '*', '_', '[', ']', '(', ')', '|', '!', '#':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
