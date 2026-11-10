package notifiers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
)

// Teams posts a plain-text message (as a legacy MessageCard's "text"
// field) to a Microsoft Teams incoming webhook.
type Teams struct {
	webhookURL string
	client     *http.Client
}

// NewTeams returns a Teams notifier posting to webhookURL.
func NewTeams(webhookURL string) *Teams {
	return &Teams{webhookURL: webhookURL, client: &http.Client{Timeout: 15 * time.Second}}
}

func (tm *Teams) Send(ctx context.Context, n alert.Notification) error {
	body, err := json.Marshal(map[string]string{"text": messageFor(n)})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tm.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tm.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("teams: unexpected status %d", resp.StatusCode)
	}
	return nil
}
