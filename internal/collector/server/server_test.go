package server_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/auth"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/server"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/sso"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/testhelpers"
)

// TestConfig_UnmarshalJSON_ParsesSnakeCaseFields proves a config file
// written in the same snake_case style as the agent's (db_path,
// auth_tokens, alert_interval_seconds, ...) is actually understood —
// Config previously had no JSON tags at all, so every one of these
// fields silently decoded to its zero value instead of erroring,
// leaving the collector running with no auth tokens, an empty (and
// therefore throwaway/temporary) database path, and alerting off.
func TestConfig_UnmarshalJSON_ParsesSnakeCaseFields(t *testing.T) {
	data := []byte(`{
		"db_path": "/var/lib/expiry-radar/radar.db",
		"listen_addr": "0.0.0.0:8443",
		"auth_tokens": ["agent-token-0123456789abcdef0123456789"],
		"admin_tokens": ["admin-token-0123456789abcdef0123456789"],
		"alert_interval_seconds": 3600,
		"webhook_url": "https://example.com/hook",
		"tls_cert_file": "/etc/radar/cert.pem",
		"tls_key_file": "/etc/radar/key.pem",
		"email": {"smtp_host": "smtp.example.com", "smtp_port": 25, "from": "a@example.com", "to": "b@example.com"}
	}`)

	var cfg server.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DBPath != "/var/lib/expiry-radar/radar.db" {
		t.Fatalf("DBPath = %q", cfg.DBPath)
	}
	if len(cfg.AuthTokens) != 1 || cfg.AuthTokens[0] != "agent-token-0123456789abcdef0123456789" {
		t.Fatalf("AuthTokens = %+v", cfg.AuthTokens)
	}
	if len(cfg.AdminTokens) != 1 || cfg.AdminTokens[0] != "admin-token-0123456789abcdef0123456789" {
		t.Fatalf("AdminTokens = %+v", cfg.AdminTokens)
	}
	if cfg.EffectiveAlertInterval() != time.Hour {
		t.Fatalf("EffectiveAlertInterval() = %v, want 1h", cfg.EffectiveAlertInterval())
	}
	if cfg.Email.SMTPHost != "smtp.example.com" || cfg.Email.SMTPPort != 25 {
		t.Fatalf("Email = %+v", cfg.Email)
	}
}

// TestRun_ReturnsErrorForInvalidConfig proves a Config missing
// required fields (here, no AuthTokens at all, which would otherwise
// leave /ingest rejecting every agent with 401) fails fast with a
// clear error rather than silently starting a non-functional server.
func TestRun_ReturnsErrorForInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := server.Config{
		DBPath:     filepath.Join(dir, "radar.db"),
		ListenAddr: "127.0.0.1:0",
		// AuthTokens intentionally left empty.
		TLSCertFile: "cert.pem",
		TLSKeyFile:  "key.pem",
	}
	if err := server.Run(cfg); err == nil {
		t.Fatal("expected an error for a Config with no AuthTokens")
	}
}

// TestRun_DashboardRequiresAdminToken proves the dashboard (and its
// mute/export endpoints) cannot be read or written by anyone who can
// merely reach the Collector's ingest endpoint — a separate admin
// token, distinct from the agents' ingest AuthTokens, must be
// required.
func TestRun_DashboardRequiresAdminToken(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testhelpers.WriteSelfSignedCertForTest(t, dir)
	cfg := server.Config{
		DBPath:      filepath.Join(dir, "radar.db"),
		ListenAddr:  "127.0.0.1:0",
		AuthTokens:  []string{"agent-token-0123456789abcdef0123456789"},
		AdminTokens: []string{"admin-token-0123456789abcdef0123456789"},
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}
	addr, stop, err := testhelpers.StartForTest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated dashboard request: got %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	auth.AttachToken(req, "admin-token-0123456789abcdef0123456789")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated dashboard request: got %d, want 200", resp.StatusCode)
	}

	// An agent ingest token must not also work as an admin token.
	req2, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	auth.AttachToken(req2, "agent-token-0123456789abcdef0123456789")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("dashboard request with an agent ingest token: got %d, want 401", resp2.StatusCode)
	}
}

// TestConfig_Validate_RejectsWeakTokens proves an empty or short token
// can never be configured. An empty string in auth_tokens would match
// a request with no Authorization header at all, opening the endpoint.
func TestConfig_Validate_RejectsWeakTokens(t *testing.T) {
	strong := "0123456789abcdef0123456789abcdef"
	base := server.Config{
		DBPath:      "radar.db",
		ListenAddr:  "127.0.0.1:0",
		AuthTokens:  []string{strong},
		AdminTokens: []string{strong + "x"},
		TLSCertFile: "cert.pem",
		TLSKeyFile:  "key.pem",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("strong config rejected: %v", err)
	}
	cases := map[string]func(c *server.Config){
		"empty agent token":  func(c *server.Config) { c.AuthTokens = []string{""} },
		"short agent token":  func(c *server.Config) { c.AuthTokens = []string{"abc"} },
		"no admin tokens":    func(c *server.Config) { c.AdminTokens = nil },
		"empty admin token":  func(c *server.Config) { c.AdminTokens = []string{""} },
		"short admin token":  func(c *server.Config) { c.AdminTokens = []string{"admin"} },
		"admin reuses agent": func(c *server.Config) { c.AdminTokens = []string{strong} },
		"unknown theme":      func(c *server.Config) { c.Theme = "blue" },
	}
	for _, ok := range []string{"", "auto", "dark", "light"} {
		c := base
		c.Theme = ok
		if err := c.Validate(); err != nil {
			t.Errorf("theme %q rejected: %v", ok, err)
		}
	}
	for name, mutate := range cases {
		c := base
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

// TestConfig_Validate_OwnerRoutes proves an owner route needs an
// owner and at least one channel, and that two routes cannot claim
// the same owner (the second would silently never be used).
func TestConfig_Validate_OwnerRoutes(t *testing.T) {
	strong := "0123456789abcdef0123456789abcdef"
	base := server.Config{
		DBPath:      "radar.db",
		ListenAddr:  "127.0.0.1:0",
		AuthTokens:  []string{strong},
		AdminTokens: []string{strong + "x"},
		TLSCertFile: "cert.pem",
		TLSKeyFile:  "key.pem",
	}
	ok := base
	ok.OwnerRoutes = []server.OwnerRoute{{Owner: "equipa-infra", SlackWebhookURL: "https://hooks.example.com/a"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid owner route rejected: %v", err)
	}
	cases := map[string]server.OwnerRoute{
		"no owner":     {SlackWebhookURL: "https://hooks.example.com/a"},
		"no channel":   {Owner: "equipa-infra"},
	}
	for name, r := range cases {
		c := base
		c.OwnerRoutes = []server.OwnerRoute{r}
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
	dup := base
	dup.OwnerRoutes = []server.OwnerRoute{
		{Owner: "equipa-infra", SlackWebhookURL: "https://hooks.example.com/a"},
		{Owner: "equipa-infra", SlackWebhookURL: "https://hooks.example.com/b"},
	}
	if err := dup.Validate(); err == nil {
		t.Error("duplicate owner route: expected a validation error")
	}
}

// TestRun_BrowserWithoutSessionRedirectsToLogin proves an
// unauthenticated browser is sent to the login page, and that the
// login page itself is reachable without authentication.
func TestRun_BrowserWithoutSessionRedirectsToLogin(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testhelpers.WriteSelfSignedCertForTest(t, dir)
	cfg := server.Config{
		DBPath:      filepath.Join(dir, "radar.db"),
		ListenAddr:  "127.0.0.1:0",
		AuthTokens:  []string{"agent-token-0123456789abcdef0123456789"},
		AdminTokens: []string{"admin-token-0123456789abcdef0123456789"},
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}
	addr, stop, err := testhelpers.StartForTest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	client := &http.Client{
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("code=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, err = client.Get("https://" + addr + "/login")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login page: got %d", resp.StatusCode)
	}
}

// TestNewHTTPServer_HasTimeouts proves slow clients cannot hold
// connections open forever (slowloris), now that /login is public.
func TestNewHTTPServer_HasTimeouts(t *testing.T) {
	srv := server.NewHTTPServer(http.NewServeMux())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("missing timeouts: %+v", srv)
	}
}

// TestRun_SetsSecurityHeaders proves every response forbids framing
// (clickjacking) and pins HTTPS (HSTS).
func TestRun_SetsSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testhelpers.WriteSelfSignedCertForTest(t, dir)
	addr, stop, err := testhelpers.StartForTest(server.Config{
		DBPath:      filepath.Join(dir, "radar.db"),
		ListenAddr:  "127.0.0.1:0",
		AuthTokens:  []string{"agent-token-0123456789abcdef0123456789"},
		AdminTokens: []string{"admin-token-0123456789abcdef0123456789"},
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + addr + "/login")
	if err != nil {
		t.Fatal(err)
	}
	h := resp.Header
	const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	if got := h.Get("Content-Security-Policy"); got != csp {
		t.Errorf("CSP = %q", got)
	}
	// The stylesheet is public: the login page needs it before sign-in.
	css, err := client.Get("https://" + addr + "/static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css.Body.Close()
	if css.StatusCode != http.StatusOK || css.Header.Get("Content-Security-Policy") != csp {
		t.Errorf("/static/app.css: %d %q", css.StatusCode, css.Header.Get("Content-Security-Policy"))
	}
	if h.Get("X-Frame-Options") != "DENY" || !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		!strings.HasPrefix(h.Get("Strict-Transport-Security"), "max-age=") || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security headers: %v", h)
	}
	// Cross-origin isolation and a closed Permissions-Policy (ZAP, OWASP
	// Secure Headers): the dashboard loads nothing from other origins and
	// needs no browser features.
	for k, want := range map[string]string{
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cross-Origin-Embedder-Policy": "require-corp",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if pp := h.Get("Permissions-Policy"); !strings.Contains(pp, "camera=()") || !strings.Contains(pp, "geolocation=()") {
		t.Errorf("Permissions-Policy = %q", pp)
	}
	// Dashboard pages and exports list the estate: never cached by the
	// browser or a proxy (ASVS 8.1.1). Static assets stay cacheable.
	for _, path := range []string{"/", "/export.json", "/history"} {
		req, _ := http.NewRequest(http.MethodGet, "https://"+addr+path, nil)
		req.Header.Set("Authorization", "Bearer admin-token-0123456789abcdef0123456789")
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if got := r.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", path, got)
		}
	}
	if got := css.Header.Get("Cache-Control"); got == "no-store" {
		t.Errorf("/static/app.css should stay cacheable, got %q", got)
	}
}

// TestConfig_SSOSessionHours proves the SSO session lifetime defaults to
// 1 hour and stays within 1..24 hours.
func TestConfig_SSOSessionHours(t *testing.T) {
	for in, want := range map[int]time.Duration{0: time.Hour, 1: time.Hour, 8: 8 * time.Hour} {
		if got := (server.Config{SSOSessionHours: in}).SSOSessionLifetime(); got != want {
			t.Errorf("%d: got %v want %v", in, got, want)
		}
	}
	base := server.Config{DBPath: "x", ListenAddr: "x", TLSCertFile: "x", TLSKeyFile: "x",
		AuthTokens: []string{"agent-token-0123456789abcdef0123456789"}, AdminTokens: []string{"admin-token-0123456789abcdef0123456789"}}
	for _, bad := range []int{-1, 25} {
		c := base
		c.SSOSessionHours = bad
		if c.Validate() == nil {
			t.Errorf("sso_session_hours %d accepted", bad)
		}
	}
}

// TestRun_UnreachableSSOProviderDoesNotBlockStartup proves an identity
// provider outage never stops the collector or the local login.
func TestRun_UnreachableSSOProviderDoesNotBlockStartup(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testhelpers.WriteSelfSignedCertForTest(t, dir)
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte("s"), 0o600)
	addr, stop, err := testhelpers.StartForTest(server.Config{
		DBPath: filepath.Join(dir, "radar.db"), ListenAddr: "127.0.0.1:0",
		AuthTokens:  []string{"agent-token-0123456789abcdef0123456789"},
		AdminTokens: []string{"admin-token-0123456789abcdef0123456789"},
		TLSCertFile: certFile, TLSKeyFile: keyFile, PublicURL: "https://collector.test",
		OIDCProviders: []sso.ProviderConfig{{Name: "down", DisplayName: "Down IdP", Issuer: "https://127.0.0.1:1",
			ClientID: "c", ClientSecretFile: secret, AllowedEmails: []string{"a@example.com"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + addr + "/login")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "Down IdP") {
		t.Fatalf("login page: %d %s", resp.StatusCode, b)
	}
	resp, err = client.Get("https://" + addr + "/auth/down/login")
	if err != nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("down provider: %v %v", resp.StatusCode, err)
	}
}

// Per-agent tokens (pentest BUSL-02): each binds one agent ID; they may
// replace the shared auth_tokens entirely.
func TestConfig_Validate_AgentCredentials(t *testing.T) {
	strong := "0123456789abcdef0123456789abcdef"
	base := server.Config{DBPath: "radar.db", ListenAddr: "127.0.0.1:0", AdminTokens: []string{strong + "admin"},
		TLSCertFile: "c", TLSKeyFile: "k",
		Agents: []server.AgentCredential{{ID: "web-01", Token: strong + "w"}, {ID: "db-01", Token: strong + "d"}}}
	if err := base.Validate(); err != nil {
		t.Fatalf("per-agent only config rejected: %v", err)
	}
	cases := map[string]func(c *server.Config){
		"no agent credential at all": func(c *server.Config) { c.Agents = nil },
		"empty id":                   func(c *server.Config) { c.Agents[0].ID = "" },
		"duplicate id":               func(c *server.Config) { c.Agents[1].ID = "web-01" },
		"short token":                func(c *server.Config) { c.Agents[0].Token = "short" },
		"token shared by two agents": func(c *server.Config) { c.Agents[1].Token = c.Agents[0].Token },
		"token also an admin token":  func(c *server.Config) { c.Agents[0].Token = c.AdminTokens[0] },
		"token also a shared token":  func(c *server.Config) { c.AuthTokens = []string{c.Agents[0].Token} },
	}
	for name, mutate := range cases {
		c := base
		c.Agents = append([]server.AgentCredential(nil), base.Agents...)
		mutate(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestRun_ReloadsRenewedCertificateWithoutRestart proves the
// collector picks up a certificate renewed on disk (as certbot would
// after a Let's Encrypt DNS-01 renewal) without needing to be
// restarted — M14: trusted TLS, part 1 (hot-reload).
func TestRun_ReloadsRenewedCertificateWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testhelpers.WriteSelfSignedCertForTest(t, dir)
	cfg := server.Config{
		DBPath:             filepath.Join(dir, "radar.db"),
		ListenAddr:         "127.0.0.1:0",
		AuthTokens:         []string{"agent-token-0123456789abcdef0123456789"},
		AdminTokens:        []string{"admin-token-0123456789abcdef0123456789"},
		TLSCertFile:        certFile,
		TLSKeyFile:         keyFile,
		CertReloadInterval: 20 * time.Millisecond,
	}
	addr, stop, err := testhelpers.StartForTest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	peerCert := func() *x509.Certificate {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- test dials its own throwaway cert
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0]
	}

	first := peerCert()

	// Simulate a renewal: a new self-signed pair written to the same
	// paths, with a clearly newer modification time.
	testhelpers.WriteSelfSignedCertForTest(t, dir)
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatalf("chtimes cert: %v", err)
	}
	if err := os.Chtimes(keyFile, future, future); err != nil {
		t.Fatalf("chtimes key: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	var second *x509.Certificate
	for time.Now().Before(deadline) {
		second = peerCert()
		if !second.Equal(first) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if second.Equal(first) {
		t.Fatal("collector kept serving the old certificate after renewal; want it reloaded without a restart")
	}
}
