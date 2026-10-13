package native

import "testing"

// TestMurmur3Vectors pins the MurmurHash3 x86_32 implementation against published
// test vectors, so the favicon fingerprint stays compatible with Shodan and Censys.
func TestMurmur3Vectors(t *testing.T) {
	cases := []struct {
		in   string
		seed uint32
		want uint32
	}{
		{"", 0, 0},
		{"", 1, 0x514E28B7},
		{"test", 0, 0xBA6BD213},
	}
	for _, c := range cases {
		if got := murmur3x86([]byte(c.in), c.seed); got != c.want {
			t.Errorf("murmur3x86(%q, %d) = %#08x, want %#08x", c.in, c.seed, got, c.want)
		}
	}
}

// TestFaviconHashIsDeterministic confirms the base64+mmh3 pipeline produces a stable,
// non-zero signed hash for a non-empty body.
func TestFaviconHashIsDeterministic(t *testing.T) {
	body := []byte("\x00\x00\x01\x00 a tiny pretend icon")
	a, b := faviconHash(body), faviconHash(body)
	if a != b {
		t.Errorf("favicon hash not deterministic: %d vs %d", a, b)
	}
	if a == 0 {
		t.Error("favicon hash of a non-empty body should not be zero")
	}
}
