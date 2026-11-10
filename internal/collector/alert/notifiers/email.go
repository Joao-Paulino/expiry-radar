package notifiers

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
)

// EmailConfig configures the Email notifier's SMTP relay.
type EmailConfig struct {
	SMTPHost string `json:"smtp_host"`
	SMTPPort int    `json:"smtp_port"`
	From     string `json:"from"`
	To       string `json:"to"`
}

// Email sends a plain-text message over SMTP, with no authentication
// (local/relay SMTP only in M1).
type Email struct {
	cfg EmailConfig
	// timeout bounds the whole SMTP exchange (dial + every command),
	// so one unresponsive relay can never block the other configured
	// notifiers from being attempted for the same alert.
	timeout time.Duration
}

// NewEmail returns an Email notifier for the given SMTP configuration.
func NewEmail(cfg EmailConfig) *Email {
	return &Email{cfg: cfg, timeout: 15 * time.Second}
}

// sanitizeHeaderValue strips CR/LF so a value taken from untrusted
// input (a certificate's Subject CN, which the scanned server
// controls) can never inject additional SMTP header lines (e.g. a
// Bcc) into the message.
func sanitizeHeaderValue(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func (e *Email) Send(ctx context.Context, n alert.Notification) error {
	addr := fmt.Sprintf("%s:%d", e.cfg.SMTPHost, e.cfg.SMTPPort)

	deadline := time.Now().Add(e.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	dialer := &net.Dialer{Timeout: e.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}

	client, err := smtp.NewClient(conn, e.cfg.SMTPHost)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Mail(e.cfg.From); err != nil {
		return err
	}
	if err := client.Rcpt(e.cfg.To); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	body := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: Expiry Radar alert: %s\r\nDate: %s\r\n\r\n%s\r\n",
		e.cfg.From, e.cfg.To, sanitizeHeaderValue(n.Record.Name), time.Now().UTC().Format(time.RFC1123Z), messageFor(n),
	)
	if _, err := w.Write([]byte(body)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
