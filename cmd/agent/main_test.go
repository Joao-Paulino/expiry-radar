package main

import (
	"os"
	"path/filepath"
	"testing"
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
