package native

import (
	"strings"
	"testing"
)

func seq(b ...byte) [][]byte {
	out := make([][]byte, len(b))
	for i, x := range b {
		out[i] = []byte{x}
	}
	return out
}

func flat(in [][]byte) string {
	var b strings.Builder
	for _, x := range in {
		b.WriteByte(x[0])
	}
	return b.String()
}

func TestCipherMungOrderings(t *testing.T) {
	five := seq(1, 2, 3, 4, 5)
	four := seq(1, 2, 3, 4)
	cases := []struct {
		in   [][]byte
		req  string
		want []byte
	}{
		{five, "REVERSE", []byte{5, 4, 3, 2, 1}},
		{five, "BOTTOM_HALF", []byte{4, 5}},
		{five, "TOP_HALF", []byte{3, 2, 1}},
		{five, "MIDDLE_OUT", []byte{3, 4, 2, 5, 1}},
		{four, "BOTTOM_HALF", []byte{3, 4}},
		{four, "TOP_HALF", []byte{2, 1}},
		{four, "MIDDLE_OUT", []byte{3, 2, 4, 1}},
		{four, "FORWARD", []byte{1, 2, 3, 4}},
	}
	for _, c := range cases {
		if got := flat(cipherMung(c.in, c.req)); got != string(c.want) {
			t.Errorf("cipherMung(%v) = %v, want %v", c.req, []byte(got), c.want)
		}
	}
}

func TestCipherIndexByte(t *testing.T) {
	for in, want := range map[string]string{
		"":     "00",
		"0004": "01", // first entry
		"0005": "02",
		"1305": "45", // last entry, index 69 = 0x45
		"ffff": "46", // unknown -> len+1 = 70 = 0x46
	} {
		if got := cipherIndexByte(in); got != want {
			t.Errorf("cipherIndexByte(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVersionByte(t *testing.T) {
	for in, want := range map[string]string{"0301": "b", "0302": "c", "0303": "d", "0304": "e", "": "0"} {
		if got := versionByte(in); got != want {
			t.Errorf("versionByte(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJarmHashEmptyAndLength(t *testing.T) {
	empty := make([]string, 10)
	for i := range empty {
		empty[i] = "|||"
	}
	if got := jarmHash(empty); got != strings.Repeat("0", 62) {
		t.Errorf("empty JARM = %q, want 62 zeros", got)
	}
	raw := make([]string, 10)
	for i := range raw {
		raw[i] = "0035|0303|h2|0000-0010-002b"
	}
	if got := jarmHash(raw); len(got) != 62 {
		t.Errorf("JARM length = %d, want 62", len(got))
	}
}
