package verify

import (
	"errors"
	"testing"
)

func TestVerifyExposedFile(t *testing.T) {
	cases := []struct {
		name     string
		reached  bool
		catchAll bool
		status   int
		body     string
		sig      string
		want     Verdict
	}{
		{"unreachable is inconclusive", false, false, 0, "", "[core]", Inconclusive},
		{"catch-all host is inconclusive", true, true, 200, "[core]", "[core]", Inconclusive},
		{"200 with signature confirms", true, false, 200, "[core]\nrepositoryformatversion = 0", "[core]", Confirmed},
		{"200 without signature refutes", true, false, 200, "<html>not found</html>", "[core]", Refuted},
		{"404 refutes", true, false, 404, "", "[core]", Refuted},
		{"403 refutes", true, false, 403, "", "[core]", Refuted},
		{"503 is inconclusive (transient)", true, false, 503, "", "[core]", Inconclusive},
		{"429 is inconclusive (transient)", true, false, 429, "", "[core]", Inconclusive},
	}
	for _, c := range cases {
		got, _ := verifyExposedFile(c.reached, c.catchAll, c.status, []byte(c.body), c.sig)
		if got != c.want {
			t.Errorf("%s: verifyExposedFile = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestVerifyTakeover(t *testing.T) {
	boom := errors.New("timeout")
	cases := []struct {
		name          string
		fingerprinted bool
		resolves      bool
		err           error
		want          Verdict
	}{
		{"no longer fingerprinted refutes", false, false, nil, Refuted},
		{"dangling target confirms", true, false, nil, Confirmed},
		{"target still resolves is inconclusive", true, true, nil, Inconclusive},
		{"resolve error is inconclusive", true, false, boom, Inconclusive},
	}
	for _, c := range cases {
		got, _ := verifyTakeover(c.fingerprinted, c.resolves, c.err)
		if got != c.want {
			t.Errorf("%s: verifyTakeover = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestVerdictConfidenceOrders(t *testing.T) {
	// A confirmation must outweigh an inconclusive check, which must outweigh a
	// refutation, so the confidence the pass records ranks them correctly.
	if !(Confirmed.confidence() > Inconclusive.confidence() && Inconclusive.confidence() > Refuted.confidence()) {
		t.Errorf("confidence order wrong: confirmed=%.2f inconclusive=%.2f refuted=%.2f",
			Confirmed.confidence(), Inconclusive.confidence(), Refuted.confidence())
	}
}
