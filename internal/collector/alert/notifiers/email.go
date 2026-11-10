package notifiers

import (
	"context"
	"fmt"
	"net/smtp"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
)

// EmailConfig configures the Email notifier's SMTP relay.
type EmailConfig struct {
	SMTPHost string
	SMTPPort int
	From     string
	To       string
}

// Email sends a plain-text message over SMTP, with no authentication
// (local/relay SMTP only in M1).
type Email struct {
	cfg EmailConfig
}

// NewEmail returns an Email notifier for the given SMTP configuration.
func NewEmail(cfg EmailConfig) *Email {
	return &Email{cfg: cfg}
}

func (e *Email) Send(ctx context.Context, n alert.Notification) error {
	addr := fmt.Sprintf("%s:%d", e.cfg.SMTPHost, e.cfg.SMTPPort)
	body := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: Expiry Radar alert: %s\r\n\r\n%s\r\n",
		e.cfg.From, e.cfg.To, n.Record.Name, messageFor(n),
	)
	return smtp.SendMail(addr, nil, e.cfg.From, []string{e.cfg.To}, []byte(body))
}
