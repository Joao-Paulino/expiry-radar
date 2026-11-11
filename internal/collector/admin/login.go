package admin

import (
	"context"
	"errors"
	"runtime"
	"strings"
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

// dummyHash is verified when no real hash exists, so every login
// attempt costs the same PBKDF2 work. Computed once at startup.
var dummyHash, _ = HashPassword("expiry-radar-unconfigured-dummy")

// lookupRecovery is a variable so tests can count calls (timing checks).
var lookupRecovery = (*Store).RecoveryCodeAvailable

// Result describes a successful login, for the audit log.
type Result struct {
	RecoveryCode      bool // a recovery code was used instead of TOTP
	RecoveryCodesLeft int  // unused recovery codes after this login
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
	_, err := a.Authenticate(ctx, password, code)
	return err
}

// Authenticate is Login that also reports how the login succeeded.
func (a *Authenticator) Authenticate(ctx context.Context, password, code string) (Result, error) {
	acc, found, err := a.Store.Get(ctx)
	if err != nil {
		return Result{}, err
	}

	hash := acc.PasswordHash
	if !found || hash == "" {
		hash = dummyHash
	}
	// Always pay for the hash first, so timing reveals nothing about
	// configuration or lock state.
	select {
	case hashSlots <- struct{}{}:
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	passwordOK, err := verifyPassword(hash, password)
	<-hashSlots
	if err != nil {
		return Result{}, err
	}

	if !found || acc.PasswordHash == "" || acc.TOTPSecret == "" {
		return Result{}, ErrNotConfigured
	}
	now := a.Now()
	// Count the attempt and check the lock in one atomic step.
	allowed, err := a.Store.ReserveAttempt(ctx, now)
	if err != nil {
		return Result{}, err
	}
	if !allowed {
		return Result{}, ErrLocked
	}

	code = strings.TrimSpace(code)
	step, totpOK := VerifyTOTP(acc.TOTPSecret, code, now, acc.TOTPLastStep)
	recoveryHash := HashRecoveryCode(strings.ToLower(code))
	if !passwordOK {
		// Same database work as the correct-password path, so timing
		// does not reveal that the password was wrong.
		if !totpOK {
			lookupRecovery(a.Store, ctx, recoveryHash)
		}
		return Result{}, ErrInvalidCredentials
	}

	if totpOK {
		claimed, err := a.Store.ClaimTOTPStep(ctx, step)
		if err != nil {
			return Result{}, err
		}
		if !claimed {
			return Result{}, ErrInvalidCredentials
		}
		return Result{}, a.Store.RecordSuccess(ctx, step)
	}

	used, err := a.Store.UseRecoveryCode(ctx, recoveryHash, now)
	if err != nil {
		return Result{}, err
	}
	if !used {
		return Result{}, ErrInvalidCredentials
	}
	if err := a.Store.RecordSuccess(ctx, 0); err != nil {
		return Result{}, err
	}
	left, err := a.Store.RecoveryCodesLeft(ctx)
	if err != nil {
		return Result{}, err
	}
	return Result{RecoveryCode: true, RecoveryCodesLeft: left}, nil
}
