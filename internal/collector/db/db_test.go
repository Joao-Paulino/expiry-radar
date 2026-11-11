package db

import (
	"database/sql"
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

// TestOpen_MigratesExistingSessionsTable proves a v0.1.x database (whose
// admin_sessions has no max_age_seconds) is upgraded in place, keeps its
// rows, and can be opened again.
func TestOpen_MigratesExistingSessionsTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "radar.db")
	old, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE admin_sessions (id_hash TEXT PRIMARY KEY, csrf_token TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL);
		INSERT INTO admin_sessions VALUES ('h','c',1,1)`); err != nil {
		t.Fatal(err)
	}
	old.Close()
	for i := 0; i < 2; i++ {
		database, err := Open(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		var maxAge int
		if err := database.QueryRow(`SELECT max_age_seconds FROM admin_sessions WHERE id_hash = 'h'`).Scan(&maxAge); err != nil || maxAge != 28800 {
			t.Fatalf("open %d: max_age_seconds=%d err=%v", i, maxAge, err)
		}
		database.Close()
	}
}
