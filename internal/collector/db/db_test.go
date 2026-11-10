package db

import (
	"path/filepath"
	"testing"
)

func TestOpen_CreatesSchema(t *testing.T) {
	dir := t.TempDir()
	database, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()

	for _, table := range []string{"expiry_records", "checker_health", "rules"} {
		var name string
		err := database.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("table %q not created: %v", table, err)
		}
	}
}
