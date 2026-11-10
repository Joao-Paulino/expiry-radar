package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig_ParsesValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	content := `{
        "collector_url": "https://collector.example.com",
        "token": "abc",
        "agent_id": "web-01",
        "queue_path": "/var/lib/expiry-radar/queue.jsonl",
        "interval_seconds": 3600,
        "tls_targets": [{"host": "mail.example.com", "port": 25, "start_tls": "smtp"}]
    }`
	os.WriteFile(path, []byte(content), 0600)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CollectorURL != "https://collector.example.com" || cfg.AgentID != "web-01" {
		t.Fatalf("got %+v", cfg)
	}
	if len(cfg.TLSTargets) != 1 || cfg.TLSTargets[0].StartTLS != "smtp" {
		t.Fatalf("got TLSTargets=%+v", cfg.TLSTargets)
	}
}

// TestConfig_Validate_RejectsMissingOrZeroFields proves a config with
// interval_seconds missing (or 0) is rejected up front: before, it
// reached time.NewTicker(0), which panics.
func TestConfig_Validate_RejectsMissingOrZeroFields(t *testing.T) {
	valid := Config{CollectorURL: "https://c", Token: "t", AgentID: "a", QueuePath: "/q", IntervalSeconds: 60}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(c *Config){
		"zero interval":     func(c *Config) { c.IntervalSeconds = 0 },
		"negative interval": func(c *Config) { c.IntervalSeconds = -5 },
		"no collector url":  func(c *Config) { c.CollectorURL = "" },
		"no token":          func(c *Config) { c.Token = "" },
		"no agent id":       func(c *Config) { c.AgentID = "" },
		"no queue path":     func(c *Config) { c.QueuePath = "" },
	}
	for name, mutate := range cases {
		c := valid
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

// TestRun_ChecksImmediatelyAtStartup proves the agent pushes a first
// batch right away instead of waiting a whole interval (an hour, by
// the documented default) before reporting anything.
func TestRun_ChecksImmediatelyAtStartup(t *testing.T) {
	pushed := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushed <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := Config{
		CollectorURL:    srv.URL + "/ingest",
		Token:           "t",
		AgentID:         "a",
		QueuePath:       filepath.Join(t.TempDir(), "queue.jsonl"),
		IntervalSeconds: 3600,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()

	select {
	case <-pushed:
	case <-time.After(3 * time.Second):
		t.Fatal("no batch pushed at startup; agent waited for the first tick")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run returned error: %v", err)
	}
}
