package notifiers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
)

// EmailConfig configures the Email notifier's SMTP server. The
// connection is always encrypted: "starttls" (the default, usually
// port 587) upgrades a plain connection and refuses to continue if the
// server does not offer STARTTLS; "tls" (usually port 465) uses TLS
// from the first byte. There is deliberately no plaintext mode.
type EmailConfig struct {
	SMTPHost string `json:"smtp_host"`
	SMTPPort int    `json:"smtp_port"`
	Security string `json:"security"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	To       string `json:"to"`
}

// Validate reports an invalid Security value.
func (c EmailConfig) Validate() error {
	switch c.Security {
	case "", "starttls", "tls":
		return nil
	default:
		return fmt.Errorf("notifiers: email security must be \"starttls\" or \"tls\", got %q", c.Security)
	}
}

// Email sends a plain-text alert over an encrypted SMTP connection,
// authenticating with Username/Password when Username is set.
type Email struct {
	cfg EmailConfig
	// timeout bounds the whole SMTP exchange (dial + every command),
	// so one unresponsive relay can never block the other configured
	// notifiers from being attempted for the same alert.
	timeout time.Duration
	// rootCAs overrides the system trust store (tests only).
	rootCAs *x509.CertPool
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

// subjectFor returns a header-safe subject line for n.
func subjectFor(n alert.Notification) string {
	prefix := "Expiry Radar alert: "
	if n.Resolved {
		prefix = "Expiry Radar resolved: "
	}
	subject := n.Record.Name
	switch n.Type {
	case alert.TypeCheckerFailed:
		subject = "checker " + n.Checker + " on " + n.Agent
	case alert.TypeAgentSilent:
		subject = "agent " + n.Agent
	}
	return sanitizeHeaderValue(prefix + subject)
}

func (e *Email) Send(ctx context.Context, n alert.Notification) error {
	if err := e.cfg.Validate(); err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%d", e.cfg.SMTPHost, e.cfg.SMTPPort)
	tlsConfig := &tls.Config{ServerName: e.cfg.SMTPHost, RootCAs: e.rootCAs, MinVersion: tls.VersionTLS12}

	deadline := time.Now().Add(e.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	netDialer := &net.Dialer{Timeout: e.timeout}
	var conn net.Conn
	var err error
	if e.cfg.Security == "tls" {
		conn, err = (&tls.Dialer{NetDialer: netDialer, Config: tlsConfig}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = netDialer.DialContext(ctx, "tcp", addr)
	}
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

	if e.cfg.Security != "tls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("notifiers: %s does not offer STARTTLS; refusing to send unencrypted", addr)
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}

	if e.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.SMTPHost)); err != nil {
			return err
		}
	}

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
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\n\r\n%s\r\n",
		e.cfg.From, e.cfg.To, subjectFor(n), time.Now().UTC().Format(time.RFC1123Z), messageFor(n),
	)
	if _, err := w.Write([]byte(body)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
