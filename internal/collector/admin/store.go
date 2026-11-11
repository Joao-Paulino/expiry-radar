package admin

import (
	"context"
	"database/sql"
	"time"
)

// MaxFailedAttempts is the account-wide backstop: after this many
// failed logins in a row, from any address, the account locks for
// lockoutDuration. The per-address throttle in the dashboard (5 per 15
// minutes) is what a single attacker hits first.
const MaxFailedAttempts = 20

const lockoutDuration = 15 * time.Minute

// Account is the single Administrator account's stored state.
type Account struct {
	PasswordHash   string
	TOTPSecret     string
	TOTPLastStep   int64
	FailedAttempts int
	LockedUntil    time.Time // zero when not locked
}

// Store persists the Administrator account in SQLite (row id = 1).
type Store struct {
	DB *sql.DB
}

// Get returns the account and whether it exists.
func (s *Store) Get(ctx context.Context) (Account, bool, error) {
	var a Account
	var lockedUntil int64
	err := s.DB.QueryRowContext(ctx, `SELECT password_hash, totp_secret, totp_last_step, failed_attempts, locked_until
		FROM admin_account WHERE id = 1`).Scan(&a.PasswordHash, &a.TOTPSecret, &a.TOTPLastStep, &a.FailedAttempts, &lockedUntil)
	if err == sql.ErrNoRows {
		return Account{}, false, nil
	}
	if err != nil {
		return Account{}, false, err
	}
	if lockedUntil > 0 {
		a.LockedUntil = time.Unix(lockedUntil, 0)
	}
	return a, true, nil
}

// SetPassword stores a new password hash and clears any lockout.
func (s *Store) SetPassword(ctx context.Context, hash string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO admin_account (id, password_hash, updated_at) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash,
			failed_attempts = 0, locked_until = 0, updated_at = excluded.updated_at`,
		hash, time.Now().Unix())
	return err
}

// SetTOTP stores a confirmed TOTP secret, resets the replay step and
// replaces all recovery codes, in one transaction.
func (s *Store) SetTOTP(ctx context.Context, secret string, recoveryHashes []string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO admin_account (id, totp_secret, updated_at) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET totp_secret = excluded.totp_secret, totp_last_step = 0,
			updated_at = excluded.updated_at`, secret, time.Now().Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM admin_recovery_codes`); err != nil {
		return err
	}
	for _, h := range recoveryHashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO admin_recovery_codes (code_hash) VALUES (?)`, h); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ReserveAttempt atomically counts one login attempt and reports
// whether it may be evaluated. It refuses (false) while the account is
// locked; the attempt that reaches MaxFailedAttempts is still allowed
// and starts the lockout. Counting and the lock decision happen in one
// statement, so concurrent attempts can never exceed the limit. An
// expired lock restarts the count, so one typo after a lockout does not
// lock the account again. A successful login resets the count
// (RecordSuccess).
func (s *Store) ReserveAttempt(ctx context.Context, now time.Time) (bool, error) {
	n := now.Unix()
	var failed int
	err := s.DB.QueryRowContext(ctx, `UPDATE admin_account
		SET failed_attempts = CASE WHEN locked_until > 0 AND locked_until <= ? THEN 1 ELSE failed_attempts + 1 END,
			locked_until = CASE
				WHEN (CASE WHEN locked_until > 0 AND locked_until <= ? THEN 1 ELSE failed_attempts + 1 END) >= ? THEN ?
				ELSE 0 END
		WHERE id = 1 AND locked_until <= ?
		RETURNING failed_attempts`,
		n, n, MaxFailedAttempts, now.Add(lockoutDuration).Unix(), n).Scan(&failed)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// RecordSuccess clears the failure counter and lockout and stores the
// accepted TOTP step (0 leaves the stored step unchanged, e.g. after a
// recovery-code login).
func (s *Store) RecordSuccess(ctx context.Context, step int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE admin_account
		SET failed_attempts = 0, locked_until = 0,
			totp_last_step = CASE WHEN ? > totp_last_step THEN ? ELSE totp_last_step END
		WHERE id = 1`, step, step)
	return err
}

// UseRecoveryCode marks the code with this hash as used; it returns
// true only the first time an existing code is used.
func (s *Store) UseRecoveryCode(ctx context.Context, hash string, now time.Time) (bool, error) {
	res, err := s.DB.ExecContext(ctx, `UPDATE admin_recovery_codes SET used_at = ?
		WHERE code_hash = ? AND used_at IS NULL`, now.Unix(), hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ClaimTOTPStep atomically records step as the last used TOTP step if
// it is newer than the stored one. It returns false when another login
// already used this (or a later) step, closing the replay race between
// concurrent logins with the same code.
func (s *Store) ClaimTOTPStep(ctx context.Context, step int64) (bool, error) {
	res, err := s.DB.ExecContext(ctx, `UPDATE admin_account SET totp_last_step = ?
		WHERE id = 1 AND totp_last_step < ?`, step, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
