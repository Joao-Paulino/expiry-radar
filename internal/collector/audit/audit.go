// Package audit records who did what: logins and later changes such
// as muting a record or changing its owner. The schema is generic
// (actor, action, target, old/new value, reason) so a future action
// (RBAC changes included) reuses it without a migration.
package audit

import (
	"context"
	"database/sql"
	"time"
)

// Entry is one audit_log row.
type Entry struct {
	ID       int64
	Actor    string
	Action   string
	Target   string
	OldValue string
	NewValue string
	Reason   string
	At       time.Time
}

// Store appends to and reads the audit_log table.
type Store struct {
	DB  *sql.DB
	Now func() time.Time
}

// Log records one action. target, oldValue, newValue and reason may be
// empty (a login has none of them).
func (s *Store) Log(ctx context.Context, actor, action, target, oldValue, newValue, reason string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO audit_log (actor, action, target, old_value, new_value, reason, at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, actor, action, target, oldValue, newValue, reason, s.Now().Unix())
	return err
}

// List returns the most recent entries, newest first, up to limit.
func (s *Store) List(ctx context.Context, limit int) ([]Entry, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, actor, action, target, old_value, new_value, reason, at
		FROM audit_log ORDER BY at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []Entry
	for rows.Next() {
		var e Entry
		var at int64
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &e.OldValue, &e.NewValue, &e.Reason, &at); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
