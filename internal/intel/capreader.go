package intel

import (
	"errors"
	"io"
)

// ErrFeedTooLarge means a feed is bigger than the size limit.
//
// A plain io.LimitReader ends in a clean EOF, so a feed larger than its cap would
// parse as a short feed, be recorded as complete, and then answer "not modified"
// forever. Reaching the limit is an error, never an ending.
var ErrFeedTooLarge = errors.New("intel: feed is larger than the size limit")

// capReader reads at most left bytes from r, and reports ErrFeedTooLarge if r has
// more to give after that.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		// The limit is spent. If the source still has data the feed was cut off by
		// the cap; if it is at its end the feed fit exactly.
		var probe [1]byte
		n, err := c.r.Read(probe[:])
		if n > 0 {
			return 0, ErrFeedTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}
