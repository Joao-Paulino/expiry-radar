package server_test

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/auth"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/server"
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
	}
	for name, mutate := range cases {
		c := base
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}
