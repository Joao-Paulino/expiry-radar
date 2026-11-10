// Package server wires up the Collector's storage, ingest endpoint,
// alert evaluation loop, and dashboard, and serves them over HTTPS.
// It is the importable core of the collector binary (cmd/collector),
// factored out so tests — including the end-to-end test — can start a
// real Collector without importing a non-importable main package.
package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/auth"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert/notifiers"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/dashboard"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/ingest"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/rules"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// Config configures the Collector, loaded by cmd/collector from a
// JSON file given as the binary's only CLI argument.
type Config struct {
	DBPath     string `json:"db_path"`
	ListenAddr string `json:"listen_addr"`
	// AuthTokens authenticate Agents pushing to /ingest.
	AuthTokens []string `json:"auth_tokens"`
	// AdminTokens authenticate the dashboard, mute/assign-owner, and
	// export endpoints — distinct from AuthTokens, so an agent's
	// ingest token can never read or mute the inventory.
	AdminTokens []string `json:"admin_tokens"`
	// AlertInterval is how code (tests, mainly) sets the alert
	// interval directly as a time.Duration. A JSON config instead sets
	// AlertIntervalSeconds, an integer number of seconds — Go's
	// encoding/json has no built-in way to parse "1h" into a
	// time.Duration, and a bare JSON number would otherwise be
	// nanoseconds, turning "3600" into a 3.6µs tight loop rather than
	// an hour. EffectiveAlertInterval reconciles the two.
	AlertInterval        time.Duration         `json:"-"`
	AlertIntervalSeconds int                   `json:"alert_interval_seconds"`
	WebhookURL           string                `json:"webhook_url"`
	SlackWebhookURL      string                `json:"slack_webhook_url"`
	TeamsWebhookURL      string                `json:"teams_webhook_url"`
	Email                notifiers.EmailConfig `json:"email"`
	TLSCertFile          string                `json:"tls_cert_file"`
	TLSKeyFile           string                `json:"tls_key_file"`

	// Ready, if non-nil, receives the actual bound address once the
	// listener starts, letting tests use ListenAddr "host:0".
	Ready chan<- string `json:"-"`
	// Done, if non-nil, signals Run to stop serving and return.
	Done <-chan struct{} `json:"-"`
}

// EffectiveAlertInterval returns AlertInterval when it's set directly
// (the common case for code/tests), otherwise AlertIntervalSeconds
// converted to a Duration (the common case for a JSON config file).
func (c Config) EffectiveAlertInterval() time.Duration {
	if c.AlertInterval > 0 {
		return c.AlertInterval
	}
	return time.Duration(c.AlertIntervalSeconds) * time.Second
}

// MinTokenLength is the shortest token Validate accepts. An empty
// token would match a request carrying no Authorization header at all;
// 32 characters is the hex encoding of 16 random bytes.
const MinTokenLength = 32

// Validate reports an error describing the first missing required
// field, so a misconfigured Collector fails fast and loudly instead
// of starting up silently non-functional (no auth tokens, an empty
// database path, no TLS files).
func (c Config) Validate() error {
	if c.DBPath == "" {
		return fmt.Errorf("server: Config.DBPath is required")
	}
	if c.ListenAddr == "" {
		return fmt.Errorf("server: Config.ListenAddr is required")
	}
	if len(c.AuthTokens) == 0 {
		return fmt.Errorf("server: Config.AuthTokens must have at least one token")
	}
	if len(c.AdminTokens) == 0 {
		return fmt.Errorf("server: Config.AdminTokens must have at least one token")
	}
	agentTokens := make(map[string]bool, len(c.AuthTokens))
	for _, tok := range c.AuthTokens {
		if len(tok) < MinTokenLength {
			return fmt.Errorf("server: every auth_tokens entry must be at least %d characters", MinTokenLength)
		}
		agentTokens[tok] = true
	}
	for _, tok := range c.AdminTokens {
		if len(tok) < MinTokenLength {
			return fmt.Errorf("server: every admin_tokens entry must be at least %d characters", MinTokenLength)
		}
		if agentTokens[tok] {
			return fmt.Errorf("server: an admin token must not also be an agent token")
		}
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return fmt.Errorf("server: Config.TLSCertFile and TLSKeyFile are required")
	}
	return nil
}

func buildNotifiers(cfg Config) []notifiers.Notifier {
	var ns []notifiers.Notifier
	if cfg.WebhookURL != "" {
		ns = append(ns, notifiers.NewWebhook(cfg.WebhookURL))
	}
	if cfg.SlackWebhookURL != "" {
		ns = append(ns, notifiers.NewSlack(cfg.SlackWebhookURL))
	}
	if cfg.TeamsWebhookURL != "" {
		ns = append(ns, notifiers.NewTeams(cfg.TeamsWebhookURL))
	}
	if cfg.Email.SMTPHost != "" {
		ns = append(ns, notifiers.NewEmail(cfg.Email))
	}
	return ns
}

func runAlertLoop(engine *alert.Engine, ns []notifiers.Notifier, interval time.Duration, done <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			notifications, err := engine.Evaluate(context.Background(), time.Now())
			if err != nil {
				log.Printf("collector: alert evaluate error: %s", logging.Sanitize(err.Error()))
				continue
			}
			for _, n := range notifications {
				if n.Muted || n.Severity == alert.SeverityOK {
					continue
				}
				for _, sendErr := range notifiers.SendAll(context.Background(), ns, n) {
					log.Printf("collector: notify error: %s", logging.Sanitize(sendErr.Error()))
				}
			}
		case <-done:
			return
		}
	}
}

// Run wires up storage, ingest, alerting, and the dashboard, then
// serves them over HTTPS until an error occurs or cfg.Done is closed.
func Run(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer database.Close()

	st := store.NewSQLite(database)
	rs := rules.NewSQLite(database)

	dashboardMux := dashboard.NewMux(st, rs)

	mux := http.NewServeMux()
	mux.Handle("/", auth.Middleware(cfg.AdminTokens, dashboardMux))
	mux.Handle("POST /ingest", auth.Middleware(cfg.AuthTokens, ingest.Handler(st)))

	if interval := cfg.EffectiveAlertInterval(); interval > 0 {
		engine := &alert.Engine{Store: st, Rules: rs, Thresholds: alert.DefaultThresholds()}
		ns := buildNotifiers(cfg)
		done := cfg.Done
		if done == nil {
			done = make(chan struct{})
		}
		go runAlertLoop(engine, ns, interval, done)
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}

	if cfg.Ready != nil {
		cfg.Ready <- listener.Addr().String()
	}

	srv := &http.Server{Handler: mux}

	if cfg.Done != nil {
		go func() {
			<-cfg.Done
			srv.Close()
		}()
	}

	err = srv.ServeTLS(listener, cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
