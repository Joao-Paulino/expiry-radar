package alert

import (
	"context"
	"database/sql"
	"time"
)

// StateStore remembers the last alert sent per alert key (in SQLite, so
// it survives restarts) and decides whether a new evaluation is worth
// notifying: a new problem, a change of severity, a resolution, or a
// reminder once the interval for that severity has passed.
type StateStore struct {
	DB *sql.DB
	// ReminderCritical and ReminderWarning re-send an unchanged alert
	// after this long; zero means never.
	ReminderCritical time.Duration
	ReminderWarning  time.Duration
}

func (s *StateStore) reminder(sev Severity) time.Duration {
	switch sev {
	case SeverityCritical:
		return s.ReminderCritical
	case SeverityWarning:
		return s.ReminderWarning
	}
	return 0
}

// Decide reports whether to send a notification for key at severity
// sev, and whether that notification is a resolution (back to OK). It
// records what was sent.
func (s *StateStore) Decide(ctx context.Context, key string, sev Severity, now time.Time) (send, resolved bool, err error) {
	var prev string
	var lastSent int64
	err = s.DB.QueryRowContext(ctx, `SELECT severity, last_sent_at FROM alert_state WHERE alert_key = ?`, key).Scan(&prev, &lastSent)
	found := err == nil
	if err != nil && err != sql.ErrNoRows {
		return false, false, err
	}

	ok := sev == SeverityOK || sev == SeverityUnknown
	switch {
	case !found && ok:
		return false, false, nil
	case found && ok:
		_, err = s.DB.ExecContext(ctx, `DELETE FROM alert_state WHERE alert_key = ?`, key)
		return err == nil, err == nil, err
	case found && Severity(prev) == sev:
		r := s.reminder(sev)
		if r <= 0 || now.Sub(time.Unix(lastSent, 0)) < r {
			return false, false, nil
		}
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO alert_state (alert_key, severity, last_sent_at) VALUES (?, ?, ?)
		ON CONFLICT(alert_key) DO UPDATE SET severity = excluded.severity, last_sent_at = excluded.last_sent_at`,
		key, string(sev), now.Unix())
	return err == nil, false, err
}

// Clear forgets key, so the next non-OK evaluation alerts again (used
// for muted records).
func (s *StateStore) Clear(ctx context.Context, key string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM alert_state WHERE alert_key = ?`, key)
	return err
}
