// Package store persists ExpiryRecords and checker health in SQLite.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// StoredRecord is an ExpiryRecord as the Collector persisted it.
type StoredRecord struct {
	checker.ExpiryRecord
	ReportedBy string    `json:"reported_by"`
	CheckedAt  time.Time `json:"checked_at"`
}

// CheckerHealth is the last known state of one checker on one agent.
type CheckerHealth struct {
	CheckerName         string
	ReportedBy          string    // agent ID
	LastSeenAt          time.Time // last report of this checker by this agent
	LastSuccessAt       time.Time // zero if it never succeeded
	ConsecutiveFailures int
	LastError           string
}

// AgentSeen is when an agent last pushed a batch.
type AgentSeen struct {
	AgentID    string
	LastSeenAt time.Time
}

// Store is the Collector's persistence interface.
type Store interface {
	// SaveRecords persists records, stamped with checkedAt — the time
	// the Agent actually ran the check, not when the Collector
	// received it. A retried batch that arrives late must still carry
	// its original check time so ListCurrent can tell it apart from a
	// newer check, rather than appearing to be the most recent one
	// just because it was inserted most recently.
	SaveRecords(ctx context.Context, agentID string, records []checker.ExpiryRecord, checkedAt time.Time) error
	// SaveResult persists one checker's run. complete means the run
	// had no error: then every item of that agent+checker it did not
	// report is gone and stops being current. A failing run may be
	// partial, so absence in it proves nothing.
	SaveResult(ctx context.Context, agentID, checkerName string, records []checker.ExpiryRecord, checkedAt time.Time, complete bool) error
	RecordCheckerHealth(ctx context.Context, checkerName, reportedBy string, checkErr error) error
	ListCurrent(ctx context.Context) ([]StoredRecord, error)
	History(ctx context.Context, source, name, kind string) ([]StoredRecord, error)
	CheckerHealth(ctx context.Context) ([]CheckerHealth, error)
	// TouchAgent marks agentID as seen now (every batch, even empty).
	TouchAgent(ctx context.Context, agentID string) error
	Agents(ctx context.Context) ([]AgentSeen, error)
	// ForgetAgent removes a decommissioned agent's health and alert
	// state, so it stops alerting; it reappears if it reports again.
	ForgetAgent(ctx context.Context, agentID string) error
}

// SQLite is a SQLite-backed Store.
type SQLite struct {
	db *sql.DB
}

// NewSQLite returns a Store backed by the given, already-migrated database.
func NewSQLite(database *sql.DB) *SQLite {
	return &SQLite{db: database}
}

func (s *SQLite) SaveRecords(ctx context.Context, agentID string, records []checker.ExpiryRecord, checkedAt time.Time) error {
	return s.SaveResult(ctx, agentID, "", records, checkedAt, false)
}

func (s *SQLite) SaveResult(ctx context.Context, agentID, checkerName string, records []checker.ExpiryRecord, checkedAt time.Time, complete bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Stored as unix nanoseconds (an integer) rather than as text:
	// comparing RFC3339Nano strings lexically is only correct if every
	// value has the same number of fractional digits, and the driver
	// trims trailing zeros, which breaks MAX(checked_at) for values
	// within the same second.
	checkedAtNanos := checkedAt.UTC().UnixNano()
	for _, r := range records {
		metadataJSON, err := json.Marshal(r.Metadata)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO expiry_records (source, name, kind, expires_at, metadata_json, reported_by, checked_at, checker_name)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, r.Source, r.Name, r.Kind, r.ExpiresAt.UTC(), string(metadataJSON), agentID, checkedAtNanos, checkerName)
		if err != nil {
			return err
		}
	}
	if complete && checkerName != "" {
		// Keep the last two complete runs. A late retried batch never
		// moves "last" back; one landing between the two becomes "prev".
		// (In UPDATE, column names refer to the old values.)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO checker_runs (agent_id, checker_name, last_complete_at, prev_complete_at) VALUES (?, ?, ?, 0)
			ON CONFLICT(agent_id, checker_name) DO UPDATE SET
				prev_complete_at = CASE
					WHEN excluded.last_complete_at > last_complete_at THEN last_complete_at
					WHEN excluded.last_complete_at < last_complete_at AND excluded.last_complete_at > prev_complete_at THEN excluded.last_complete_at
					ELSE prev_complete_at END,
				last_complete_at = MAX(last_complete_at, excluded.last_complete_at)
		`, agentID, checkerName, checkedAtNanos); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) RecordCheckerHealth(ctx context.Context, checkerName, reportedBy string, checkErr error) error {
	now := time.Now().Unix()
	if checkErr == nil {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO agent_checker_health (agent_id, checker_name, last_seen_at, last_success_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(agent_id, checker_name) DO UPDATE SET last_seen_at = excluded.last_seen_at,
				last_success_at = excluded.last_success_at, consecutive_failures = 0, last_error = ''
		`, reportedBy, checkerName, now, now)
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agent_checker_health (agent_id, checker_name, last_seen_at, consecutive_failures, last_error)
		VALUES (?, ?, ?, 1, ?)
		ON CONFLICT(agent_id, checker_name) DO UPDATE SET last_seen_at = excluded.last_seen_at,
			consecutive_failures = consecutive_failures + 1, last_error = excluded.last_error
	`, reportedBy, checkerName, now, checkErr.Error())
	return err
}

// ListCurrent returns, per (source, name, kind), the newest row among
// the agents that still report it. An agent's newest row for an item is
// gone only when that agent and checker then completed two error-free
// runs without it (one is not enough: a load balancer may alternate
// certificates). Runs with errors never hide anything. Rows from before
// checker names were stored (”) are gone once every checker the agent
// reports has done that. A forgotten agent's rows (checker '*', agent
// clock) are gone until it reports again. Missing an expiry alert is
// worse than a stale one, so every doubt keeps the row.
func (s *SQLite) ListCurrent(ctx context.Context) ([]StoredRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		WITH per_agent AS (
			SELECT e.* FROM expiry_records e
			WHERE e.checked_at = (
				SELECT MAX(checked_at) FROM expiry_records x
				WHERE x.source = e.source AND x.name = e.name AND x.kind = e.kind AND x.reported_by = e.reported_by
			)
		),
		live AS (
			SELECT * FROM per_agent e
			WHERE NOT EXISTS (
				SELECT 1 FROM checker_runs r
				WHERE r.agent_id = e.reported_by AND r.checker_name = '*' AND r.last_complete_at >= e.checked_at
			)
			AND NOT (e.checker_name <> '' AND EXISTS (
				SELECT 1 FROM checker_runs r
				WHERE r.agent_id = e.reported_by AND r.checker_name = e.checker_name AND r.prev_complete_at > e.checked_at
			))
			AND NOT (e.checker_name = ''
				AND EXISTS (SELECT 1 FROM agent_checker_health h WHERE h.agent_id = e.reported_by)
				AND NOT EXISTS (
					SELECT 1 FROM agent_checker_health h
					WHERE h.agent_id = e.reported_by AND NOT EXISTS (
						SELECT 1 FROM checker_runs r
						WHERE r.agent_id = h.agent_id AND r.checker_name = h.checker_name AND r.prev_complete_at > e.checked_at
					)
				))
		)
		SELECT source, name, kind, expires_at, metadata_json, reported_by, checked_at
		FROM live l
		WHERE l.checked_at = (
			SELECT MAX(checked_at) FROM live y
			WHERE y.source = l.source AND y.name = l.name AND y.kind = l.kind
		)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanStoredRecords(rows)
}

func (s *SQLite) History(ctx context.Context, source, name, kind string) ([]StoredRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT source, name, kind, expires_at, metadata_json, reported_by, checked_at
		FROM expiry_records
		WHERE source = ? AND name = ? AND kind = ?
		ORDER BY checked_at ASC
	`, source, name, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanStoredRecords(rows)
}

func scanStoredRecords(rows *sql.Rows) ([]StoredRecord, error) {
	var records []StoredRecord
	for rows.Next() {
		var rec StoredRecord
		var metadataJSON string
		var checkedAtNanos int64
		if err := rows.Scan(&rec.Source, &rec.Name, &rec.Kind, &rec.ExpiresAt, &metadataJSON, &rec.ReportedBy, &checkedAtNanos); err != nil {
			return nil, err
		}
		rec.CheckedAt = time.Unix(0, checkedAtNanos).UTC()
		if metadataJSON != "" && metadataJSON != "null" {
			if err := json.Unmarshal([]byte(metadataJSON), &rec.Metadata); err != nil {
				return nil, err
			}
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

func (s *SQLite) CheckerHealth(ctx context.Context) ([]CheckerHealth, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT checker_name, agent_id, last_seen_at, last_success_at, consecutive_failures, last_error
		FROM agent_checker_health ORDER BY agent_id, checker_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []CheckerHealth
	for rows.Next() {
		var h CheckerHealth
		var seen, success int64
		if err := rows.Scan(&h.CheckerName, &h.ReportedBy, &seen, &success, &h.ConsecutiveFailures, &h.LastError); err != nil {
			return nil, err
		}
		h.LastSeenAt = time.Unix(seen, 0).UTC()
		if success > 0 {
			h.LastSuccessAt = time.Unix(success, 0).UTC()
		}
		results = append(results, h)
	}
	return results, rows.Err()
}

func (s *SQLite) TouchAgent(ctx context.Context, agentID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO agents (agent_id, last_seen_at) VALUES (?, ?)
		ON CONFLICT(agent_id) DO UPDATE SET last_seen_at = excluded.last_seen_at`, agentID, time.Now().Unix())
	return err
}

func (s *SQLite) Agents(ctx context.Context) ([]AgentSeen, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT agent_id, last_seen_at FROM agents ORDER BY agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentSeen
	for rows.Next() {
		var a AgentSeen
		var seen int64
		if err := rows.Scan(&a.AgentID, &seen); err != nil {
			return nil, err
		}
		a.LastSeenAt = time.Unix(seen, 0).UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLite) ForgetAgent(ctx context.Context, agentID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM agents WHERE agent_id = ?`, []any{agentID}},
		{`DELETE FROM agent_checker_health WHERE agent_id = ?`, []any{agentID}},
		// Its items are gone up to its newest report, on its own clock
		// (see ListCurrent: checker '*'); anything newer shows again.
		{`INSERT INTO checker_runs (agent_id, checker_name, last_complete_at)
			VALUES (?, '*', (SELECT COALESCE(MAX(checked_at), 0) FROM expiry_records WHERE reported_by = ?))
			ON CONFLICT(agent_id, checker_name) DO UPDATE SET last_complete_at = excluded.last_complete_at`,
			[]any{agentID, agentID}},
		{`DELETE FROM alert_state WHERE alert_key = ? OR substr(alert_key, 1, ?) = ?`,
			[]any{"agent|" + agentID, len("checker|" + agentID + "|"), "checker|" + agentID + "|"}},
	} {
		if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}
