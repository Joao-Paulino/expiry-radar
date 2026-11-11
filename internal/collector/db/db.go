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

-- When each agent last completed a run of each checker without errors
-- (unix nanoseconds of the check). An item missing from such a run is
-- gone; see store.ListCurrent.
CREATE TABLE IF NOT EXISTS checker_runs (
    agent_id TEXT NOT NULL,
    checker_name TEXT NOT NULL,
    last_complete_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, checker_name)
);

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

-- Per agent and checker; replaces checker_health (kept only so old
-- databases still open).
CREATE TABLE IF NOT EXISTS agent_checker_health (
    agent_id TEXT NOT NULL,
    checker_name TEXT NOT NULL,
    last_seen_at INTEGER NOT NULL,           -- unix seconds
    last_success_at INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (agent_id, checker_name)
);

-- Every agent that pushed a batch, even with no checker results.
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    last_seen_at INTEGER NOT NULL -- unix seconds, collector clock
);

-- Last alert sent per alert key, for deduplication.
CREATE TABLE IF NOT EXISTS alert_state (
    alert_key TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    last_sent_at INTEGER NOT NULL
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
    last_seen_at INTEGER NOT NULL,
    max_age_seconds INTEGER NOT NULL DEFAULT 28800 -- absolute lifetime
);

-- Pending SSO logins: state (hashed), nonce and PKCE verifier; 10 min, single use.
CREATE TABLE IF NOT EXISTS sso_flows (
    state_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    nonce TEXT NOT NULL,
    verifier TEXT NOT NULL,
    created_at INTEGER NOT NULL
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
	if err := migrate(database); err != nil {
		database.Close()
		return nil, err
	}
	return database, nil
}

// migrate upgrades tables created by older versions, where CREATE TABLE
// IF NOT EXISTS cannot add columns.
func migrate(database *sql.DB) error {
	if err := addColumnIfMissing(database, "admin_sessions", "max_age_seconds", "INTEGER NOT NULL DEFAULT 28800"); err != nil {
		return err
	}
	// Rows written before checker_name existed keep '' (see store.ListCurrent).
	return addColumnIfMissing(database, "expiry_records", "checker_name", "TEXT NOT NULL DEFAULT ''")
}

func addColumnIfMissing(database *sql.DB, table, column, decl string) error {
	rows, err := database.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	_, err = database.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + decl)
	return err
}
