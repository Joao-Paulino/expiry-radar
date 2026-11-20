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
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/auth"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/admin"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/audit"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert/notifiers"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/dashboard"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/ingest"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/rules"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/sso"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// Config configures the Collector, loaded by cmd/collector from a
// JSON file given as the binary's only CLI argument.
type Config struct {
	DBPath     string `json:"db_path"`
	ListenAddr string `json:"listen_addr"`
	// AuthTokens authenticate Agents pushing to /ingest. They are
	// shared: a holder can report as any agent ID. Prefer Agents.
	AuthTokens []string `json:"auth_tokens"`
	// Agents are per-agent tokens: each may only report as its own ID,
	// so one compromised agent host cannot hide another agent's items.
	Agents []AgentCredential `json:"agents"`
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
	ReminderCriticalHours *int `json:"reminder_critical_hours"` // default 24, 0 = never
	ReminderWarningHours  *int `json:"reminder_warning_hours"`  // default 0 = never
	CheckerFailThreshold  int  `json:"checker_fail_threshold"`  // default 3
	AgentStaleHours       int  `json:"agent_stale_hours"`       // default 3
	// SSO (OIDC). PublicURL is the HTTPS address browsers use, for
	// redirect URIs. SSOSessionHours bounds SSO sessions (default 1, max 24).
	PublicURL       string                `json:"public_url"`
	OIDCProviders   []sso.ProviderConfig  `json:"oidc_providers"`
	SSOSessionHours int                   `json:"sso_session_hours"`
	WebhookURL      string                `json:"webhook_url"`
	SlackWebhookURL string                `json:"slack_webhook_url"`
	TeamsWebhookURL string                `json:"teams_webhook_url"`
	Email           notifiers.EmailConfig `json:"email"`
	// OwnerRoutes sends a record's expiry alert to its own owner's
	// channels instead of the global ones above, when the record's
	// rules.Rule.Owner matches a route's Owner. An owner with no
	// matching route still falls back to the global channels.
	OwnerRoutes []OwnerRoute `json:"owner_routes"`
	// Theme is the dashboard's default colour scheme: "auto" (follow
	// the OS, the default), "dark" or "light"; each browser may override it.
	Theme       string `json:"theme"`
	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`

	// Ready, if non-nil, receives the actual bound address once the
	// listener starts, letting tests use ListenAddr "host:0".
	Ready chan<- string `json:"-"`
	// Done, if non-nil, signals Run to stop serving and return.
	Done <-chan struct{} `json:"-"`
}

// OwnerRoute sends TypeExpiry alerts for a record whose rules.Rule.Owner
// matches Owner to these channels instead of the global ones, and only
// to these — never also to the global channels, so a routed owner's
// items never duplicate into the general one.
type OwnerRoute struct {
	Owner           string                `json:"owner"`
	WebhookURL      string                `json:"webhook_url"`
	SlackWebhookURL string                `json:"slack_webhook_url"`
	TeamsWebhookURL string                `json:"teams_webhook_url"`
	Email           notifiers.EmailConfig `json:"email"`
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

// SSOSessionLifetime is the maximum lifetime of an SSO session.
func (c Config) SSOSessionLifetime() time.Duration {
	if c.SSOSessionHours <= 0 {
		return time.Hour
	}
	return time.Duration(c.SSOSessionHours) * time.Hour
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
	switch c.Theme {
	case "", "auto", "dark", "light":
	default:
		return fmt.Errorf("server: theme must be auto, dark or light")
	}
	if len(c.AuthTokens) == 0 && len(c.Agents) == 0 {
		return fmt.Errorf("server: configure agents (per-agent tokens) or auth_tokens")
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
	ids := map[string]bool{}
	for _, a := range c.Agents {
		if strings.TrimSpace(a.ID) == "" {
			return fmt.Errorf("server: every agents entry needs an id")
		}
		if ids[a.ID] {
			return fmt.Errorf("server: agent id %q is listed twice", a.ID)
		}
		ids[a.ID] = true
		if len(a.Token) < MinTokenLength {
			return fmt.Errorf("server: the token of agent %q must be at least %d characters", a.ID, MinTokenLength)
		}
		if agentTokens[a.Token] {
			return fmt.Errorf("server: the token of agent %q is already used by another agent or auth_tokens", a.ID)
		}
		agentTokens[a.Token] = true
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
	if c.SSOSessionHours < 0 || c.SSOSessionHours > 24 {
		return fmt.Errorf("server: sso_session_hours must be between 1 and 24 (0 means the default, 1)")
	}
	if len(c.OIDCProviders) > 0 {
		if err := sso.ValidateProviders(c.OIDCProviders, c.PublicURL); err != nil {
			return err
		}
	}
	if c.Email.SMTPHost != "" {
		if err := c.Email.Validate(); err != nil {
			return err
		}
	}
	seenOwners := map[string]bool{}
	for _, r := range c.OwnerRoutes {
		if r.Owner == "" {
			return fmt.Errorf("server: every owner_routes entry needs an owner")
		}
		if seenOwners[r.Owner] {
			return fmt.Errorf("server: owner %q is listed twice in owner_routes", r.Owner)
		}
		seenOwners[r.Owner] = true
		if r.WebhookURL == "" && r.SlackWebhookURL == "" && r.TeamsWebhookURL == "" && r.Email.SMTPHost == "" {
			return fmt.Errorf("server: owner_routes entry %q needs at least one channel (webhook_url, slack_webhook_url, teams_webhook_url or email)", r.Owner)
		}
		if r.Email.SMTPHost != "" {
			if err := r.Email.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

// channels is the set of notification channels one config block (the
// global one, or one OwnerRoute) can configure.
type channels struct {
	WebhookURL      string
	SlackWebhookURL string
	TeamsWebhookURL string
	Email           notifiers.EmailConfig
}

func buildNotifiersFrom(c channels) []notifiers.Notifier {
	var ns []notifiers.Notifier
	if c.WebhookURL != "" {
		ns = append(ns, notifiers.NewWebhook(c.WebhookURL))
	}
	if c.SlackWebhookURL != "" {
		ns = append(ns, notifiers.NewSlack(c.SlackWebhookURL))
	}
	if c.TeamsWebhookURL != "" {
		ns = append(ns, notifiers.NewTeams(c.TeamsWebhookURL))
	}
	if c.Email.SMTPHost != "" {
		ns = append(ns, notifiers.NewEmail(c.Email))
	}
	return ns
}

func buildNotifiers(cfg Config) []notifiers.Notifier {
	return buildNotifiersFrom(channels{WebhookURL: cfg.WebhookURL, SlackWebhookURL: cfg.SlackWebhookURL,
		TeamsWebhookURL: cfg.TeamsWebhookURL, Email: cfg.Email})
}

// buildOwnerRoutes returns each configured OwnerRoute's own channels,
// keyed by owner, for deliver to pick over the global channels.
func buildOwnerRoutes(routes []OwnerRoute) map[string][]notifiers.Notifier {
	if len(routes) == 0 {
		return nil
	}
	out := make(map[string][]notifiers.Notifier, len(routes))
	for _, r := range routes {
		out[r.Owner] = buildNotifiersFrom(channels{WebhookURL: r.WebhookURL, SlackWebhookURL: r.SlackWebhookURL,
			TeamsWebhookURL: r.TeamsWebhookURL, Email: r.Email})
	}
	return out
}

// deliver runs one alert cycle: evaluate everything, then send only
// what StateStore says is new, changed, resolved or due a reminder.
// Muted subjects send nothing and are forgotten, so unmuting a
// still-failing record alerts again.
// deliver sends each due notification through ns, the global
// channels, except when the notification has an Owner that matches a
// key in routes: that owner's own channels are used instead of ns, so
// a routed owner's items never also duplicate into the global
// channel. An owner with no matching route (or no owner at all) still
// falls back to ns.
func deliver(ctx context.Context, engine *alert.Engine, state *alert.StateStore, ns []notifiers.Notifier, routes map[string][]notifiers.Notifier, now time.Time) {
	notifications, err := engine.Evaluate(ctx, now)
	if err != nil {
		log.Printf("collector: alert evaluate error: %s", logging.Sanitize(err.Error()))
		return
	}
	evaluated := map[string]bool{}
	for _, n := range notifications {
		evaluated[n.Key()] = true
	}
	notifications = append(notifications, goneResolutions(ctx, engine, state, evaluated)...)
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
		targets := ns
		if n.Owner != "" {
			if r, ok := routes[n.Owner]; ok {
				targets = r
			}
		}
		errs := notifiers.SendAll(ctx, targets, n)
		for _, sendErr := range errs {
			log.Printf("collector: notify error: %s", logging.Sanitize(sendErr.Error()))
		}
		// Remember it only if at least one channel delivered it (or none
		// is configured); otherwise retry next cycle.
		if len(targets) == 0 || len(errs) < len(targets) {
			if err := state.Commit(ctx, key, n.Severity, now); err != nil {
				log.Printf("collector: alert state error: %s", logging.Sanitize(err.Error()))
			}
		}
	}
}

// goneResolutions returns an OK notification for every open expiry
// alert whose item is no longer current (deleted, renamed, rotated
// away, or its agent forgotten), so the alert is resolved once instead
// of staying open.
func goneResolutions(ctx context.Context, engine *alert.Engine, state *alert.StateStore, evaluated map[string]bool) []alert.Notification {
	keys, err := state.OpenKeys(ctx, "expiry|")
	if err != nil {
		log.Printf("collector: alert state error: %s", logging.Sanitize(err.Error()))
		return nil
	}
	var out []alert.Notification
	for _, k := range keys {
		if evaluated[k] {
			continue
		}
		rest := strings.TrimPrefix(k, "expiry|")
		i, j := strings.Index(rest, "|"), strings.LastIndex(rest, "|")
		if i < 0 || j <= i {
			continue
		}
		var r store.StoredRecord
		r.Source, r.Name, r.Kind = rest[:i], rest[i+1:j], rest[j+1:]
		muted := false
		if engine.Rules != nil {
			if rule, found, err := engine.Rules.Get(ctx, r.Source, r.Name, r.Kind); err == nil && found {
				muted = rule.Muted
			}
		}
		out = append(out, alert.Notification{Type: alert.TypeExpiry, Record: r, Severity: alert.SeverityOK, Gone: true, Muted: muted,
			Detail: "no longer reported (deleted, renamed or rotated away)"})
	}
	return out
}

func runAlertLoop(engine *alert.Engine, state *alert.StateStore, ns []notifiers.Notifier, routes map[string][]notifiers.Notifier, interval time.Duration, done <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			deliver(context.Background(), engine, state, ns, routes, time.Now())
		case <-done:
			return
		}
	}
}

// securityHeaders allows only the Collector's own scripts, styles and
// form targets (CSP), and forbids framing (clickjacking), MIME sniffing and,
// since the Collector only serves HTTPS, pins browsers to HTTPS.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Referrer-Policy", "no-referrer")
		// Cross-origin isolation: nothing here is meant to be embedded,
		// opened by, or loaded from another origin.
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), clipboard-read=()")
		// Pages and exports list the monitored estate: keep them out of
		// browser and proxy caches. The static handler sets its own policy.
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// runSessionCleanup deletes expired sessions every interval until done.
func runSessionCleanup(sessions *session.Store, flows *sso.FlowStore, interval time.Duration, done <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if _, err := sessions.DeleteExpired(context.Background()); err != nil {
				log.Printf("collector: session cleanup error: %s", logging.Sanitize(err.Error()))
			}
			if _, err := flows.DeleteExpired(context.Background()); err != nil {
				log.Printf("collector: SSO flow cleanup error: %s", logging.Sanitize(err.Error()))
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
	if len(cfg.AuthTokens) > 0 {
		log.Printf("collector: auth_tokens are shared: any agent holding one can report as any agent ID. Prefer per-agent tokens: collector add-agent <config> <id>")
	}
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
	auditLog := &audit.Store{DB: database, Now: time.Now}

	dashboardMux := dashboard.NewMux(st, rs, auditLog, dashboard.Options{Theme: cfg.Theme})

	sessions := &session.Store{DB: database, Now: time.Now}
	authenticator := &admin.Authenticator{Store: &admin.Store{DB: database}, Now: time.Now}
	ssoHandlers := &sso.Handlers{
		Providers: cfg.OIDCProviders, PublicURL: cfg.PublicURL, Sessions: sessions, Audit: auditLog,
		Flows: &sso.FlowStore{DB: database, Now: time.Now}, SessionLifetime: cfg.SSOSessionLifetime(),
		HTTPClient: &http.Client{Timeout: 15 * time.Second}, // discovery, token and signing-key requests
	}
	loginGet, loginPost, logout, revokeAll := dashboard.LoginHandlers(authenticator, sessions, auditLog, ssoHandlers.Buttons(), dashboard.Options{Theme: cfg.Theme})

	mux := http.NewServeMux()
	mux.Handle("GET /static/", dashboard.StaticHandler())
	mux.Handle("GET /login", loginGet)
	mux.Handle("POST /login", loginPost)
	mux.Handle("POST /logout", session.Middleware(sessions, cfg.AdminTokens, logout))
	mux.Handle("POST /sessions/revoke-all", session.Middleware(sessions, cfg.AdminTokens, revokeAll))
	if len(cfg.OIDCProviders) > 0 {
		ssoHandlers.Register(mux)
	}
	mux.Handle("/", session.Middleware(sessions, cfg.AdminTokens, dashboardMux))
	mux.Handle("POST /ingest", auth.AgentMiddleware(cfg.agentCredentials(), ingest.Handler(st)))

	if interval := cfg.EffectiveAlertInterval(); interval > 0 {
		engine := &alert.Engine{Store: st, Rules: rs, Thresholds: alert.DefaultThresholds(),
			FailThreshold: cfg.checkerFailThreshold(), StaleAfter: cfg.agentStaleAfter()}
		state := &alert.StateStore{DB: database, ReminderCritical: cfg.reminderCritical(), ReminderWarning: cfg.reminderWarning()}
		ns := buildNotifiers(cfg)
		routes := buildOwnerRoutes(cfg.OwnerRoutes)
		done := cfg.Done
		if done == nil {
			done = make(chan struct{})
		}
		go runAlertLoop(engine, state, ns, routes, interval, done)
	}

	cleanupDone := cfg.Done
	if cleanupDone == nil {
		cleanupDone = make(chan struct{})
	}
	go runSessionCleanup(sessions, ssoHandlers.Flows, 10*time.Minute, cleanupDone)

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
			_ = srv.Close()
		}()
	}

	err = srv.ServeTLS(listener, cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// AgentCredential is a per-agent token: pushes made with Token may only
// report as agent ID.
type AgentCredential struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

// agentCredentials merges the per-agent tokens and the shared ones.
func (c Config) agentCredentials() []auth.Credential {
	out := make([]auth.Credential, 0, len(c.Agents)+len(c.AuthTokens))
	for _, a := range c.Agents {
		out = append(out, auth.Credential{Token: a.Token, AgentID: a.ID})
	}
	for _, t := range c.AuthTokens {
		out = append(out, auth.Credential{Token: t})
	}
	return out
}
