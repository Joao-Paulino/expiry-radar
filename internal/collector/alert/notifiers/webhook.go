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

// Webhook POSTs a generic JSON payload for each notification.
type Webhook struct {
	url    string
	client *http.Client
}

// NewWebhook returns a Webhook notifier posting to url.
func NewWebhook(url string) *Webhook {
	return &Webhook{url: url, client: &http.Client{Timeout: 15 * time.Second}}
}

type webhookPayload struct {
	Severity  string    `json:"severity"`
	Source    string    `json:"source"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	ExpiresAt time.Time `json:"expires_at"`
}

func payloadFor(n alert.Notification) webhookPayload {
	return webhookPayload{
		Severity:  string(n.Severity),
		Source:    n.Record.Source,
		Name:      n.Record.Name,
		Kind:      n.Record.Kind,
		ExpiresAt: n.Record.ExpiresAt,
	}
}

// Send posts the notification as JSON to the configured webhook URL.
func (w *Webhook) Send(ctx context.Context, n alert.Notification) error {
	body, err := json.Marshal(payloadFor(n))
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: unexpected status %d", resp.StatusCode)
	}
	return nil
}
