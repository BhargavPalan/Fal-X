package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// webhookAttempts is how many times a webhook POST is tried before giving up, so a
// transient failure does not silently drop an alert that the diff window will not resurface.
const webhookAttempts = 3

// Webhook POSTs the events as JSON to url, retrying a transient failure (a transport error,
// 429, or 5xx) with backoff and giving up on a permanent 4xx. A failed alert is returned so
// the caller can log it, but never stops monitoring. An empty event set posts nothing.
func Webhook(ctx context.Context, client *http.Client, url string, events []ChangeEvent) error {
	if len(events) == 0 {
		return nil
	}
	payload := struct {
		At     time.Time     `json:"at"`
		Count  int           `json:"count"`
		Events []ChangeEvent `json:"events"`
	}{At: time.Now().UTC(), Count: len(events), Events: events}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := range webhookAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		status, err := postOnce(ctx, client, url, body)
		if err != nil {
			lastErr = err
			continue // a transport error is transient: retry
		}
		if status >= 200 && status < 300 {
			return nil
		}
		lastErr = fmt.Errorf("monitor: webhook returned HTTP %d", status)
		if status != http.StatusTooManyRequests && status < 500 {
			return lastErr // a permanent 4xx will not improve on retry
		}
	}
	return lastErr
}

// postOnce sends one POST and returns the status code, closing the body.
func postOnce(ctx context.Context, client *http.Client, url string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "fal-x")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // drain so the connection can be reused
	return resp.StatusCode, nil
}
