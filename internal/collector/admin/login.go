package admin

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	// ErrInvalidCredentials means the password or the code was wrong.
	ErrInvalidCredentials = errors.New("admin: invalid credentials")
	// ErrLocked means too many recent failures; the account is locked.
	ErrLocked = errors.New("admin: account locked")
	// ErrNotConfigured means the password or TOTP has not been set up.
	ErrNotConfigured = errors.New("admin: administrator login not configured")
)

// verifyPassword is a variable so tests can count calls (timing checks).
var verifyPassword = VerifyPassword

var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// dummyPasswordHash is verified when no real hash exists, so every
// login attempt costs the same PBKDF2 work.
func dummyPasswordHash() string {
	dummyHashOnce.Do(func() {
		dummyHash, _ = HashPassword("expiry-radar-unconfigured-dummy")
	})
	return dummyHash
}

// Authenticator checks Administrator logins: password, then a TOTP or
// recovery code, with lockout after repeated failures.
type Authenticator struct {
	Store *Store
	Now   func() time.Time
}

// Login returns nil only for the correct password plus a valid,
// unused TOTP code or recovery code, on an unlocked, fully configured
// account. Callers must show the same message for every error.
func (a *Authenticator) Login(ctx context.Context, password, code string) error {
	acc, found, err := a.Store.Get(ctx)
	if err != nil {
		return err
	}

	hash := acc.PasswordHash
	if !found || hash == "" {
		hash = dummyPasswordHash()
	}
	// Always pay for the hash first, so timing reveals nothing about
	// configuration or lock state.
	passwordOK, err := verifyPassword(hash, password)
	if err != nil {
		return err
	}

	if !found || acc.PasswordHash == "" || acc.TOTPSecret == "" {
		return ErrNotConfigured
	}
	now := a.Now()
	if acc.LockedUntil.After(now) {
		return ErrLocked
	}
	if !passwordOK {
		return a.fail(ctx, now)
	}

	code = strings.TrimSpace(code)
	if step, ok := VerifyTOTP(acc.TOTPSecret, code, now, acc.TOTPLastStep); ok {
		claimed, err := a.Store.ClaimTOTPStep(ctx, step)
		if err != nil {
			return err
		}
		if !claimed {
			return a.fail(ctx, now)
		}
		return a.Store.RecordSuccess(ctx, step)
	}

	used, err := a.Store.UseRecoveryCode(ctx, HashRecoveryCode(strings.ToLower(code)), now)
	if err != nil {
		return err
	}
	if !used {
		return a.fail(ctx, now)
	}
	return a.Store.RecordSuccess(ctx, 0)
}

func (a *Authenticator) fail(ctx context.Context, now time.Time) error {
	locked, err := a.Store.RecordFailure(ctx, now)
	if err != nil {
		return err
	}
	if locked {
		return ErrLocked
	}
	return ErrInvalidCredentials
}
