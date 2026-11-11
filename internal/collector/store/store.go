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

// Store is the Collector's persistence interface.
type Store interface {
	// SaveRecords persists records, stamped with checkedAt — the time
	// the Agent actually ran the check, not when the Collector
	// received it. A retried batch that arrives late must still carry
	// its original check time so ListCurrent can tell it apart from a
	// newer check, rather than appearing to be the most recent one
	// just because it was inserted most recently.
	SaveRecords(ctx context.Context, agentID string, records []checker.ExpiryRecord, checkedAt time.Time) error
	RecordCheckerHealth(ctx context.Context, checkerName, reportedBy string, checkErr error) error
	ListCurrent(ctx context.Context) ([]StoredRecord, error)
	History(ctx context.Context, source, name, kind string) ([]StoredRecord, error)
	CheckerHealth(ctx context.Context) ([]CheckerHealth, error)
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
		_, err = s.db.ExecContext(ctx, `
			INSERT INTO expiry_records (source, name, kind, expires_at, metadata_json, reported_by, checked_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, r.Source, r.Name, r.Kind, r.ExpiresAt.UTC(), string(metadataJSON), agentID, checkedAtNanos)
		if err != nil {
			return err
		}
	}
	return nil
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

func (s *SQLite) ListCurrent(ctx context.Context) ([]StoredRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT source, name, kind, expires_at, metadata_json, reported_by, checked_at
		FROM expiry_records e
		WHERE checked_at = (
			SELECT MAX(checked_at) FROM expiry_records
			WHERE source = e.source AND name = e.name AND kind = e.kind
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
