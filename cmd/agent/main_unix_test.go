//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The config file holds the agent token: a world/group-readable file
// must be refused, the same way sshd refuses a loose private key.
func TestLoadConfig_RejectsGroupOrOtherReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	content := `{"collector_url":"https://collector.example.com","token":"abc","agent_id":"web-01","queue_path":"/var/lib/expiry-radar/queue.jsonl","interval_seconds":3600}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("want an error for a group/other-readable config file")
	}
}
