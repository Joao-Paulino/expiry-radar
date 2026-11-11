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

// messageFor is the one-line alert text shared by Slack, Teams and email.
func messageFor(n alert.Notification) string {
	tag := "[" + string(n.Severity) + "]"
	if n.Resolved {
		tag = "[resolved]"
	}
	switch n.Type {
	case alert.TypeCheckerFailed:
		if n.Resolved {
			return fmt.Sprintf("%s checker %s on agent %s is working again", tag, n.Checker, n.Agent)
		}
		return fmt.Sprintf("%s checker %s keeps failing on agent %s: %s", tag, n.Checker, n.Agent, n.Detail)
	case alert.TypeAgentSilent:
		if n.Resolved {
			return fmt.Sprintf("%s agent %s is reporting again", tag, n.Agent)
		}
		return fmt.Sprintf("%s agent %s stopped reporting", tag, n.Agent)
	default:
		r := n.Record
		if n.Gone {
			return fmt.Sprintf("%s %s/%s (%s) is no longer reported (deleted, renamed or rotated away); verify it was removed on purpose", tag, r.Source, r.Name, r.Kind)
		}
		if n.Resolved {
			return fmt.Sprintf("%s %s/%s (%s) no longer near expiry, now expires at %s", tag, r.Source, r.Name, r.Kind, r.ExpiresAt.Format(time.RFC3339))
		}
		return fmt.Sprintf("%s %s/%s (%s) expires at %s", tag, r.Source, r.Name, r.Kind, r.ExpiresAt.Format(time.RFC3339))
	}
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
