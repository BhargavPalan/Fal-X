package stage

import (
	"time"
)

// censysTick is the pause between Censys lookups.
//
// The free tier allows one request per second. Waiting is explicit here rather
// than relying on being rate limited, which produces a partial result and an
// error instead of a complete one.
const censysTick = time.Second

// newTicker returns the rate-limiter channel used between Censys lookups.
func newTicker() *time.Ticker { return time.NewTicker(censysTick) }
