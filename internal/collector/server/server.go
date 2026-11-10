// Package server wires up the Collector's storage, ingest endpoint,
// alert evaluation loop, and dashboard, and serves them over HTTPS.
// It is the importable core of the collector binary (cmd/collector),
// factored out so tests — including the end-to-end test — can start a
// real Collector without importing a non-importable main package.
package server

import (
	"context"
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
	DBPath     string
	ListenAddr string
	// AuthTokens authenticate Agents pushing to /ingest.
	AuthTokens []string
	// AdminTokens authenticate the dashboard, mute/assign-owner, and
	// export endpoints — distinct from AuthTokens, so an agent's
	// ingest token can never read or mute the inventory.
	AdminTokens     []string
	AlertInterval   time.Duration
	WebhookURL      string
	SlackWebhookURL string
	TeamsWebhookURL string
	Email           notifiers.EmailConfig
	TLSCertFile     string
	TLSKeyFile      string

	// Ready, if non-nil, receives the actual bound address once the
	// listener starts, letting tests use ListenAddr "host:0".
	Ready chan<- string `json:"-"`
	// Done, if non-nil, signals Run to stop serving and return.
	Done <-chan struct{} `json:"-"`
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

	if cfg.AlertInterval > 0 {
		engine := &alert.Engine{Store: st, Rules: rs, Thresholds: alert.DefaultThresholds()}
		ns := buildNotifiers(cfg)
		done := cfg.Done
		if done == nil {
			done = make(chan struct{})
		}
		go runAlertLoop(engine, ns, cfg.AlertInterval, done)
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
