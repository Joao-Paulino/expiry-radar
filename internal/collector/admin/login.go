package admin

import (
	"context"
	"errors"
	"runtime"
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

// hashSlots bounds how many PBKDF2 computations run at once, so the
// public /login endpoint cannot be used to exhaust the CPU and starve
// ingest and alerting. Extra requests wait their turn.
var hashSlots = make(chan struct{}, max(1, runtime.NumCPU()/2))

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
	select {
	case hashSlots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	passwordOK, err := verifyPassword(hash, password)
	<-hashSlots
	if err != nil {
		return err
	}

	if !found || acc.PasswordHash == "" || acc.TOTPSecret == "" {
		return ErrNotConfigured
	}
	now := a.Now()
	// Count the attempt and check the lock in one atomic step.
	allowed, err := a.Store.ReserveAttempt(ctx, now)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrLocked
	}
	if !passwordOK {
		return ErrInvalidCredentials
	}

	code = strings.TrimSpace(code)
	if step, ok := VerifyTOTP(acc.TOTPSecret, code, now, acc.TOTPLastStep); ok {
		claimed, err := a.Store.ClaimTOTPStep(ctx, step)
		if err != nil {
			return err
		}
		if !claimed {
			return ErrInvalidCredentials
		}
		return a.Store.RecordSuccess(ctx, step)
	}

	used, err := a.Store.UseRecoveryCode(ctx, HashRecoveryCode(strings.ToLower(code)), now)
	if err != nil {
		return err
	}
	if !used {
		return ErrInvalidCredentials
	}
	return a.Store.RecordSuccess(ctx, 0)
}
