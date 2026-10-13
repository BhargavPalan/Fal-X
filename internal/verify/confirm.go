package verify

import (
	"bytes"
	"fmt"
)

// Verdict is the result of re-checking a reported exposure against the live target.
type Verdict string

const (
	// Confirmed means the evidence is still present, so the finding holds now.
	Confirmed Verdict = "confirmed"
	// Refuted means the evidence is gone, so the finding no longer holds.
	Refuted Verdict = "refuted"
	// Inconclusive means the target could not be reached or the result is ambiguous, so
	// the finding is neither confirmed nor cleared.
	Inconclusive Verdict = "inconclusive"
)

// confidence is the weight to attach to a verdict: a confirmation is near-certain, a
// refutation leaves the stale finding at low weight, and an inconclusive check neither
// raises nor lowers much.
func (v Verdict) confidence() float64 {
	switch v {
	case Confirmed:
		return 0.95
	case Refuted:
		return 0.2
	default:
		return 0.5
	}
}

// verifyExposedFile decides whether a reported exposed file is still served. A reachable
// 200 carrying the file's signature confirms it; a 200 without the signature or a 4xx
// refutes it (the path was fixed, or it was a soft 404); a host that answers 200 to any
// path (catchAll), a transient 429/5xx, or an unreachable host is inconclusive — none is
// evidence the file was removed, and a catch-all would match any weak signature.
func verifyExposedFile(reached, catchAll bool, status int, body []byte, signature string) (Verdict, string) {
	if !reached {
		return Inconclusive, "the host did not respond"
	}
	if catchAll {
		return Inconclusive, "the host answers 200 to unknown paths, so a body match cannot be trusted"
	}
	if status == 200 && bytes.Contains(body, []byte(signature)) {
		return Confirmed, fmt.Sprintf("HTTP 200 and the %q signature is present", signature)
	}
	if status == 200 {
		return Refuted, "HTTP 200 but the expected signature is absent"
	}
	if status == 429 || status >= 500 {
		return Inconclusive, fmt.Sprintf("HTTP %d is transient, not evidence the file is gone", status)
	}
	return Refuted, fmt.Sprintf("HTTP %d", status)
}

// verifyTakeover decides whether a reported subdomain-takeover candidate is still
// dangling. The CNAME must still point at a takeover-prone service (else the risk is
// gone); if that target no longer resolves it is unclaimed and the takeover is
// confirmed; if it still resolves the state is ambiguous without a claim attempt, which
// verification never makes, so it stays inconclusive.
func verifyTakeover(cnameStillFingerprinted, targetResolves bool, resolveErr error) (Verdict, string) {
	if !cnameStillFingerprinted {
		return Refuted, "the CNAME no longer points at a takeover-prone service"
	}
	if resolveErr != nil {
		return Inconclusive, "the CNAME target could not be resolved cleanly"
	}
	if !targetResolves {
		return Confirmed, "the CNAME target is unclaimed (does not resolve)"
	}
	return Inconclusive, "the CNAME target still resolves; a claim check is out of scope for verification"
}
