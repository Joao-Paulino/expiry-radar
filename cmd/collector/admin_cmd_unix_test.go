//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The config file holds admin tokens, SMTP password, client secrets:
// a world/group-readable file must be refused.
func TestLoadConfig_RejectsGroupOrOtherReadable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "collector.json")
	if err := os.WriteFile(p, []byte(`{"db_path":"x.db"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(p); err == nil {
		t.Fatal("want an error for a group/other-readable config file")
	}
}
