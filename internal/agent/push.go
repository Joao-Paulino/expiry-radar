// Package agent implements the Agent's push client, local retry
// queue, and checker runner.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/auth"
	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// Pusher pushes batches to the Collector's ingest endpoint over
// authenticated HTTPS.
type Pusher struct {
	collectorURL string
	token        string
	client       *http.Client
}

// NewPusher returns a Pusher for the given Collector URL and bearer token.
func NewPusher(collectorURL, token string) *Pusher {
	return &Pusher{
		collectorURL: collectorURL,
		token:        token,
		client:       &http.Client{Timeout: 15 * time.Second},
	}
}

// HTTPClient returns the Pusher's underlying http.Client, so callers
// (tests, mainly) can adjust its Transport — e.g. to trust a
// self-signed Collector certificate.
func (p *Pusher) HTTPClient() *http.Client {
	return p.client
}

// Push sends b to the Collector's ingest endpoint and returns an error
// if the request fails or the response is not 204 No Content.
func (p *Pusher) Push(ctx context.Context, b checker.Batch) error {
	body, err := json.Marshal(b)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.collectorURL+"/ingest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	auth.AttachToken(req, p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("push: collector returned status %d", resp.StatusCode)
	}
	return nil
}
