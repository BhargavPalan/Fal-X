package main

import "strings"

// orUnset renders an empty value as a placeholder, so a missing feed version or
// field reads as "(unset)" rather than a blank column.
func orUnset(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(unset)"
	}
	return s
}
