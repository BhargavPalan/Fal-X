package match

import "strings"

// token is a run of digits or a run of letters from a version string.
type token struct {
	numeric bool
	text    string
}

func tokens(v string) []token {
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	var out []token
	for i := 0; i < len(v); {
		switch c := v[i]; {
		case c >= '0' && c <= '9':
			j := i
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			out = append(out, token{true, strings.TrimLeft(v[i:j], "0")})
			i = j
		case c >= 'a' && c <= 'z':
			j := i
			for j < len(v) && v[j] >= 'a' && v[j] <= 'z' {
				j++
			}
			out = append(out, token{false, v[i:j]})
			i = j
		default:
			i++
		}
	}
	return out
}

// postRelease lists the letter runs that mean "a later patch of this version", as
// in OpenSSH's 6.6.1p1. Every other letter run (alpha, beta, rc, dev) sorts before
// the plain release.
var postRelease = map[string]bool{"p": true, "pl": true, "sp": true, "patch": true}

// Compare orders two version strings: negative when a is older, zero when they are
// the same version, positive when a is newer.
//
// Vendors do not share a version scheme, so this is a pragmatic ordering and not a
// parser of any one of them. Numbers compare as numbers, so 2.4.10 is later than
// 2.4.9. A missing component counts as zero, so 1.0 equals 1.0.0. Letters compare
// alphabetically, and a pre-release word sorts before the release it precedes.
func Compare(a, b string) int {
	ta, tb := tokens(a), tokens(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		x, y := tokenAt(ta, i), tokenAt(tb, i)
		if c := compareTokens(x, y); c != 0 {
			return c
		}
	}
	return 0
}

func tokenAt(ts []token, i int) token {
	if i < len(ts) {
		return ts[i]
	}
	return token{numeric: true}
}

func compareTokens(x, y token) int {
	switch {
	case x.numeric && y.numeric:
		if len(x.text) != len(y.text) {
			return sign(len(x.text) - len(y.text))
		}
		return strings.Compare(x.text, y.text)
	case !x.numeric && !y.numeric:
		return strings.Compare(x.text, y.text)
	case !x.numeric:
		if postRelease[x.text] {
			return 1
		}
		return -1
	default:
		if postRelease[y.text] {
			return -1
		}
		return 1
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// Range is a set of versions bounded at either end. An empty bound is open.
type Range struct {
	StartIncluding, StartExcluding string
	EndIncluding, EndExcluding     string
}

// Contains reports whether version lies inside the range.
func (r Range) Contains(version string) bool {
	if r.StartIncluding != "" && Compare(version, r.StartIncluding) < 0 {
		return false
	}
	if r.StartExcluding != "" && Compare(version, r.StartExcluding) <= 0 {
		return false
	}
	if r.EndIncluding != "" && Compare(version, r.EndIncluding) > 0 {
		return false
	}
	if r.EndExcluding != "" && Compare(version, r.EndExcluding) >= 0 {
		return false
	}
	return true
}

// Bounded reports whether the range has any bound.
func (r Range) Bounded() bool {
	return r.StartIncluding != "" || r.StartExcluding != "" || r.EndIncluding != "" || r.EndExcluding != ""
}
