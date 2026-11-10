// Package rules persists mute/assign-owner rules for expiry records.
package rules

import (
	"context"
	"database/sql"
	"errors"
)

// Rule is a per-(source,name,kind) mute/owner override.
type Rule struct {
	Source string
	Name   string
	Kind   string
	Muted  bool
	Owner  string
}

// Store is the rules persistence interface.
type Store interface {
	Get(ctx context.Context, source, name, kind string) (Rule, bool, error)
	Upsert(ctx context.Context, r Rule) error
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

func (s *SQLite) Upsert(ctx context.Context, r Rule) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO rules (source, name, kind, muted, owner)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(source, name, kind) DO UPDATE SET muted = excluded.muted, owner = excluded.owner
	`, r.Source, r.Name, r.Kind, r.Muted, r.Owner)
	return err
}

func (s *SQLite) Get(ctx context.Context, source, name, kind string) (Rule, bool, error) {
	var muted bool
	var owner string
	err := s.db.QueryRowContext(ctx, `SELECT muted, owner FROM rules WHERE source = ? AND name = ? AND kind = ?`, source, name, kind).Scan(&muted, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, false, nil
	}
	if err != nil {
		return Rule{}, false, err
	}
	return Rule{Source: source, Name: name, Kind: kind, Muted: muted, Owner: owner}, true, nil
}

func (s *SQLite) List(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source, name, kind, muted, owner FROM rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.Source, &r.Name, &r.Kind, &r.Muted, &r.Owner); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
