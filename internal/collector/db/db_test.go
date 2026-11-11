package db

import (
	"os"
	"path/filepath"
	"runtime"
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

// TestOpen_PathWithSpecialCharacters proves a db_path containing URL
// metacharacters opens exactly that file, not a truncated path.
func TestOpen_PathWithSpecialCharacters(t *testing.T) {
	names := []string{"hash#dir", "pct%20dir", "space dir"}
	if runtime.GOOS != "windows" { // '?' is not a valid Windows file name character
		names = append(names, "question?dir")
	}
	for _, name := range names {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "radar.db")
		database, err := Open(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		database.Close()
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: database not created at %s: %v", name, path, err)
		}
	}
}
