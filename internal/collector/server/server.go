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
	"github.com/Joao-Paulino/expiry-radar/internal/collector/admin"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert/notifiers"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/dashboard"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/ingest"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/rules"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
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
	AlertInterval        time.Duration `json:"-"`
	AlertIntervalSeconds int           `json:"alert_interval_seconds"`
	// Alert noise and health settings (see README); nil/0 = default.
	ReminderCriticalHours *int                  `json:"reminder_critical_hours"` // default 24, 0 = never
	ReminderWarningHours  *int                  `json:"reminder_warning_hours"`  // default 0 = never
	CheckerFailThreshold  int                   `json:"checker_fail_threshold"`  // default 3
	AgentStaleHours       int                   `json:"agent_stale_hours"`       // default 3
	WebhookURL            string                `json:"webhook_url"`
	SlackWebhookURL       string                `json:"slack_webhook_url"`
	TeamsWebhookURL       string                `json:"teams_webhook_url"`
	Email                 notifiers.EmailConfig `json:"email"`
	TLSCertFile           string                `json:"tls_cert_file"`
	TLSKeyFile            string                `json:"tls_key_file"`

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

func hoursOr(p *int, def int) time.Duration {
	if p == nil {
		return time.Duration(def) * time.Hour
	}
	return time.Duration(*p) * time.Hour
}

func (c Config) reminderCritical() time.Duration { return hoursOr(c.ReminderCriticalHours, 24) }
func (c Config) reminderWarning() time.Duration  { return hoursOr(c.ReminderWarningHours, 0) }

func (c Config) checkerFailThreshold() int {
	if c.CheckerFailThreshold > 0 {
		return c.CheckerFailThreshold
	}
	return 3
}

func (c Config) agentStaleAfter() time.Duration {
	if c.AgentStaleHours > 0 {
		return time.Duration(c.AgentStaleHours) * time.Hour
	}
	return 3 * time.Hour
}

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
	if c.Email.SMTPHost != "" {
		if err := c.Email.Validate(); err != nil {
			return err
		}
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

// deliver runs one alert cycle: evaluate everything, then send only
// what StateStore says is new, changed, resolved or due a reminder.
// Muted subjects send nothing and are forgotten, so unmuting a
// still-failing record alerts again.
func deliver(ctx context.Context, engine *alert.Engine, state *alert.StateStore, ns []notifiers.Notifier, now time.Time) {
	notifications, err := engine.Evaluate(ctx, now)
	if err != nil {
		log.Printf("collector: alert evaluate error: %s", logging.Sanitize(err.Error()))
		return
	}
	for _, n := range notifications {
		key := n.Key()
		if n.Muted {
			if err := state.Clear(ctx, key); err != nil {
				log.Printf("collector: alert state error: %s", logging.Sanitize(err.Error()))
			}
			continue
		}
		send, resolved, err := state.Decide(ctx, key, n.Severity, now)
		if err != nil {
			log.Printf("collector: alert state error: %s", logging.Sanitize(err.Error()))
			continue
		}
		if !send {
			continue
		}
		n.Resolved = resolved
		errs := notifiers.SendAll(ctx, ns, n)
		for _, sendErr := range errs {
			log.Printf("collector: notify error: %s", logging.Sanitize(sendErr.Error()))
		}
		// Remember it only if at least one channel delivered it (or none
		// is configured); otherwise retry next cycle.
		if len(ns) == 0 || len(errs) < len(ns) {
			if err := state.Commit(ctx, key, n.Severity, now); err != nil {
				log.Printf("collector: alert state error: %s", logging.Sanitize(err.Error()))
			}
		}
	}
}

func runAlertLoop(engine *alert.Engine, state *alert.StateStore, ns []notifiers.Notifier, interval time.Duration, done <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			deliver(context.Background(), engine, state, ns, time.Now())
		case <-done:
			return
		}
	}
}

// securityHeaders forbids framing (clickjacking), MIME sniffing and,
// since the Collector only serves HTTPS, pins browsers to HTTPS.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// runSessionCleanup deletes expired sessions every interval until done.
func runSessionCleanup(sessions *session.Store, interval time.Duration, done <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if _, err := sessions.DeleteExpired(context.Background()); err != nil {
				log.Printf("collector: session cleanup error: %s", logging.Sanitize(err.Error()))
			}
		case <-done:
			return
		}
	}
}

// NewHTTPServer returns the Collector's HTTP server with timeouts, so
// slow or idle clients cannot hold connections open indefinitely.
func NewHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
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

	sessions := &session.Store{DB: database, Now: time.Now}
	authenticator := &admin.Authenticator{Store: &admin.Store{DB: database}, Now: time.Now}
	loginGet, loginPost, logout := dashboard.LoginHandlers(authenticator, sessions)

	mux := http.NewServeMux()
	mux.Handle("GET /login", loginGet)
	mux.Handle("POST /login", loginPost)
	mux.Handle("POST /logout", session.Middleware(sessions, cfg.AdminTokens, logout))
	mux.Handle("/", session.Middleware(sessions, cfg.AdminTokens, dashboardMux))
	mux.Handle("POST /ingest", auth.Middleware(cfg.AuthTokens, ingest.Handler(st)))

	if interval := cfg.EffectiveAlertInterval(); interval > 0 {
		engine := &alert.Engine{Store: st, Rules: rs, Thresholds: alert.DefaultThresholds(),
			FailThreshold: cfg.checkerFailThreshold(), StaleAfter: cfg.agentStaleAfter()}
		state := &alert.StateStore{DB: database, ReminderCritical: cfg.reminderCritical(), ReminderWarning: cfg.reminderWarning()}
		ns := buildNotifiers(cfg)
		done := cfg.Done
		if done == nil {
			done = make(chan struct{})
		}
		go runAlertLoop(engine, state, ns, interval, done)
	}

	cleanupDone := cfg.Done
	if cleanupDone == nil {
		cleanupDone = make(chan struct{})
	}
	go runSessionCleanup(sessions, 10*time.Minute, cleanupDone)

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}

	if cfg.Ready != nil {
		cfg.Ready <- listener.Addr().String()
	}

	srv := NewHTTPServer(securityHeaders(mux))

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
