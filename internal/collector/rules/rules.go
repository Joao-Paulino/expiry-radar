// Package rules persists mute/assign-owner rules for expiry records.
package rules

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Rule is a per-(source,name,kind) mute/owner override. MuteReason is
// mandatory whenever Muted is true (enforced by the caller, e.g. the
// dashboard handler, not here). MuteUntil is the mute's expiry; the
// zero value means no expiry.
type Rule struct {
	Source     string
	Name       string
	Kind       string
	Muted      bool
	Owner      string
	MuteReason string
	MuteUntil  time.Time
}

// ActiveMute reports whether the rule is a mute that is still in
// effect at now: muted, and either with no expiry or not yet expired.
// A mute past its MuteUntil auto-expires without anyone unmuting it.
func (r Rule) ActiveMute(now time.Time) bool {
	return r.Muted && (r.MuteUntil.IsZero() || now.Before(r.MuteUntil))
}

// Store is the rules persistence interface.
type Store interface {
	// Get returns the rule for one item; found is false when it has none.
	Get(ctx context.Context, source, name, kind string) (Rule, bool, error)
	// Upsert creates or replaces the rule for r's source, name and kind.
	Upsert(ctx context.Context, r Rule) error
	// List returns every rule.
	List(ctx context.Context) ([]Rule, error)
}

// SQLite is a SQLite-backed Store.
type SQLite struct {
	db *sql.DB
}

// NewSQLite returns a Store backed by the given, already-migrated database.
func NewSQLite(database *sql.DB) *SQLite {
	return &SQLite{db: database}
}

// Upsert implements Store.
func (s *SQLite) Upsert(ctx context.Context, r Rule) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO rules (source, name, kind, muted, owner, mute_reason, mute_until)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source, name, kind) DO UPDATE SET
			muted = excluded.muted, owner = excluded.owner,
			mute_reason = excluded.mute_reason, mute_until = excluded.mute_until
	`, r.Source, r.Name, r.Kind, r.Muted, r.Owner, r.MuteReason, muteUntilUnix(r.MuteUntil))
	return err
}

// Get implements Store.
func (s *SQLite) Get(ctx context.Context, source, name, kind string) (Rule, bool, error) {
	var muted bool
	var owner, reason string
	var until int64
	err := s.db.QueryRowContext(ctx, `SELECT muted, owner, mute_reason, mute_until FROM rules WHERE source = ? AND name = ? AND kind = ?`, source, name, kind).
		Scan(&muted, &owner, &reason, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, false, nil
	}
	if err != nil {
		return Rule{}, false, err
	}
	return Rule{Source: source, Name: name, Kind: kind, Muted: muted, Owner: owner,
		MuteReason: reason, MuteUntil: unixToMuteUntil(until)}, true, nil
}

// List implements Store.
func (s *SQLite) List(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source, name, kind, muted, owner, mute_reason, mute_until FROM rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []Rule
	for rows.Next() {
		var r Rule
		var until int64
		if err := rows.Scan(&r.Source, &r.Name, &r.Kind, &r.Muted, &r.Owner, &r.MuteReason, &until); err != nil {
			return nil, err
		}
		r.MuteUntil = unixToMuteUntil(until)
		result = append(result, r)
	}
	return result, rows.Err()
}

// muteUntilUnix/unixToMuteUntil store MuteUntil as a unix-seconds
// integer, 0 meaning "no expiry" (matching time.Time{}'s zero value).
func muteUntilUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func unixToMuteUntil(u int64) time.Time {
	if u == 0 {
		return time.Time{}
	}
	return time.Unix(u, 0).UTC()
}
