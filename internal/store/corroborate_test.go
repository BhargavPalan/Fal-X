package store

import (
	"math"
	"testing"
	"time"
)

func TestDecay(t *testing.T) {
	// Fresh: unchanged. One half-life: halved. Very old: floored, never zero.
	if got := Decay(0.8, 0); got != 0.8 {
		t.Errorf("Decay fresh = %v, want 0.8", got)
	}
	if got := Decay(0.8, decayHalfLife); math.Abs(got-0.4) > 1e-9 {
		t.Errorf("Decay at one half-life = %v, want 0.4", got)
	}
	if got := Decay(0.8, 10*decayHalfLife); got < 0.8*decayFloor-1e-9 || got > 0.8*decayFloor+1e-9 {
		t.Errorf("Decay very old = %v, want the floored %v", got, 0.8*decayFloor)
	}
	// Monotone non-increasing with age.
	prev := Decay(0.9, 0)
	for _, d := range []time.Duration{time.Hour, 24 * time.Hour, decayHalfLife, 3 * decayHalfLife} {
		got := Decay(0.9, d)
		if got > prev {
			t.Errorf("Decay not monotone at %v: %v > %v", d, got, prev)
		}
		prev = got
	}
}

func TestCorroborate(t *testing.T) {
	// One source: unchanged. More sources: higher, saturating toward 1, never above it.
	if got := Corroborate(0.6, 1); math.Abs(got-0.6) > 1e-9 {
		t.Errorf("Corroborate(0.6,1) = %v, want 0.6", got)
	}
	if got := Corroborate(0.6, 2); math.Abs(got-0.84) > 1e-9 {
		t.Errorf("Corroborate(0.6,2) = %v, want 0.84", got)
	}
	if got := Corroborate(0.5, 0); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("Corroborate(0.5,0) should treat n<1 as 1, got %v", got)
	}
	prev := 0.0
	for n := 1; n <= 6; n++ {
		got := Corroborate(0.5, n)
		if got < prev || got > 1 {
			t.Errorf("Corroborate not monotone/≤1 at n=%d: %v", n, got)
		}
		prev = got
	}
}
