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

// Slack posts a plain-text message to a Slack incoming webhook.
type Slack struct {
	webhookURL string
	client     *http.Client
}

// NewSlack returns a Slack notifier posting to webhookURL.
func NewSlack(webhookURL string) *Slack {
	return &Slack{webhookURL: webhookURL, client: &http.Client{Timeout: 15 * time.Second}}
}

func messageFor(n alert.Notification) string {
	p := payloadFor(n)
	return fmt.Sprintf("[%s] %s/%s (%s) expires at %s", p.Severity, p.Source, p.Name, p.Kind, p.ExpiresAt.Format(time.RFC3339))
}

func (s *Slack) Send(ctx context.Context, n alert.Notification) error {
	body, err := json.Marshal(map[string]string{"text": messageFor(n)})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack: unexpected status %d", resp.StatusCode)
	}
	return nil
}
