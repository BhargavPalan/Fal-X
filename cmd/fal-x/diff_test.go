package main

import (
	"testing"
	"time"
)

func TestParseSince(t *testing.T) {
	now := time.Now()
	if got, err := parseSince("24h"); err != nil || now.Sub(got) < 23*time.Hour || now.Sub(got) > 25*time.Hour {
		t.Errorf("parseSince(24h) = %v, err=%v", got, err)
	}
	if got, err := parseSince("2026-01-02T03:04:05Z"); err != nil || got.Year() != 2026 {
		t.Errorf("parseSince(RFC3339) = %v, err=%v", got, err)
	}
	if _, err := parseSince("not-a-time"); err == nil {
		t.Error("parseSince should reject an unparseable value")
	}
}
