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
// sev, and whether it is a resolution (back to OK). It changes nothing:
// call Commit once the notification was actually delivered, so a failed
// delivery is retried on the next cycle instead of being lost.
func (s *StateStore) Decide(ctx context.Context, key string, sev Severity, now time.Time) (send, resolved bool, err error) {
	var prev string
	var lastSent int64
	err = s.DB.QueryRowContext(ctx, `SELECT severity, last_sent_at FROM alert_state WHERE alert_key = ?`, key).Scan(&prev, &lastSent)
	if err == sql.ErrNoRows {
		return sev != SeverityOK && sev != SeverityUnknown, false, nil
	}
	if err != nil {
		return false, false, err
	}
	switch {
	case sev == SeverityOK || sev == SeverityUnknown:
		return true, true, nil
	case Severity(prev) != sev:
		return true, false, nil
	}
	r := s.reminder(sev)
	return r > 0 && now.Sub(time.Unix(lastSent, 0)) >= r, false, nil
}

// Commit records that a notification for key at sev was delivered at
// now; a resolution (OK) forgets the key.
func (s *StateStore) Commit(ctx context.Context, key string, sev Severity, now time.Time) error {
	if sev == SeverityOK || sev == SeverityUnknown {
		return s.Clear(ctx, key)
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO alert_state (alert_key, severity, last_sent_at) VALUES (?, ?, ?)
		ON CONFLICT(alert_key) DO UPDATE SET severity = excluded.severity, last_sent_at = excluded.last_sent_at`,
		key, string(sev), now.Unix())
	return err
}

// Clear forgets key, so the next non-OK evaluation alerts again (used
// for muted records).
func (s *StateStore) Clear(ctx context.Context, key string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM alert_state WHERE alert_key = ?`, key)
	return err
}

// OpenKeys lists the alert keys starting with prefix that have an open
// (unresolved) alert.
func (s *StateStore) OpenKeys(ctx context.Context, prefix string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT alert_key FROM alert_state WHERE substr(alert_key, 1, ?) = ?`, len(prefix), prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
