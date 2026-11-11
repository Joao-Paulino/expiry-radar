// Package db bootstraps the Collector's SQLite database and runs all
// schema migrations.
package db

import (
	"database/sql"

	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

const schema = `
CREATE TABLE IF NOT EXISTS expiry_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    metadata_json TEXT NOT NULL,
    reported_by TEXT NOT NULL,
    checked_at INTEGER NOT NULL -- unix nanoseconds; see store.SaveRecords
);
CREATE INDEX IF NOT EXISTS idx_expiry_records_key ON expiry_records(source, name, kind);

CREATE TABLE IF NOT EXISTS checker_health (
    checker_name TEXT PRIMARY KEY,
    last_success_at DATETIME,
    last_error TEXT NOT NULL DEFAULT '',
    reported_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rules (
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    muted BOOLEAN NOT NULL DEFAULT 0,
    owner TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (source, name, kind)
);

CREATE TABLE IF NOT EXISTS admin_account (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL DEFAULT '',
    totp_secret TEXT NOT NULL DEFAULT '',
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0, -- unix seconds, 0 = not locked
    updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS admin_recovery_codes (
    code_hash TEXT PRIMARY KEY,
    used_at INTEGER
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id_hash TEXT PRIMARY KEY,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);
`

// Open opens (creating if absent) a SQLite database at path and runs
// all schema migrations.
func Open(path string) (*sql.DB, error) {
	// A plain path (not a "file:" URI) is taken literally, so '#', '?'
	// and '%' are safe and Windows drive letters work; for plain paths
	// the ncruces driver also sets a one-minute busy timeout, so
	// concurrent writers wait for the lock instead of failing.
	database, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	if _, err := database.Exec(schema); err != nil {
		database.Close()
		return nil, err
	}
	return database, nil
}
