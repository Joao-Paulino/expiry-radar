package admin

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testPassword = "correct horse battery staple"

type loginFixture struct {
	auth     *Authenticator
	store    *Store
	secret   string
	recovery []string
	now      time.Time
}

func newLoginFixture(t *testing.T) *loginFixture {
	t.Helper()
	ctx := context.Background()
	st := newTestStore(t)
	f := &loginFixture{store: st, now: time.Unix(1_700_000_000, 0)}
	f.auth = &Authenticator{Store: st, Now: func() time.Time { return f.now }}
	h, err := HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	st.SetPassword(ctx, h)
	f.secret, _ = NewTOTPSecret()
	plain, hashes, _ := NewRecoveryCodes()
	f.recovery = plain
	st.SetTOTP(ctx, f.secret, hashes)
	return f
}

func (f *loginFixture) code(t *testing.T) string {
	c, err := TOTPCode(f.secret, f.now.Unix()/30)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLogin_NotConfigured(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	a := &Authenticator{Store: st, Now: time.Now}
	if err := a.Login(ctx, testPassword, "123456"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("empty DB: got %v", err)
	}
	h, _ := HashPassword(testPassword)
	st.SetPassword(ctx, h)
	if err := a.Login(ctx, testPassword, "123456"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("password without TOTP: got %v", err)
	}
}

func TestLogin_Success(t *testing.T) {
	f := newLoginFixture(t)
	if err := f.auth.Login(context.Background(), testPassword, f.code(t)); err != nil {
		t.Fatalf("got %v", err)
	}
}

func TestLogin_WrongPasswordRecordsFailure(t *testing.T) {
	f := newLoginFixture(t)
	if err := f.auth.Login(context.Background(), "wrong password!!", f.code(t)); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got %v", err)
	}
	acc, _, _ := f.store.Get(context.Background())
	if acc.FailedAttempts != 1 {
		t.Fatalf("failures = %d", acc.FailedAttempts)
	}
}

func TestLogin_WrongCode(t *testing.T) {
	f := newLoginFixture(t)
	bad := "000000"
	if bad == f.code(t) {
		bad = "111111"
	}
	if err := f.auth.Login(context.Background(), testPassword, bad); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got %v", err)
	}
}

func TestLogin_RecoveryCodeWorksOnce(t *testing.T) {
	f := newLoginFixture(t)
	ctx := context.Background()
	if err := f.auth.Login(ctx, testPassword, f.recovery[0]); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := f.auth.Login(ctx, testPassword, f.recovery[0]); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("second use: %v", err)
	}
}

func TestLogin_SameTOTPCodeTwiceRejected(t *testing.T) {
	f := newLoginFixture(t)
	ctx := context.Background()
	code := f.code(t)
	if err := f.auth.Login(ctx, testPassword, code); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.Login(ctx, testPassword, code); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("replayed code: got %v", err)
	}
}

func TestLogin_ConcurrentSameCodeOnlyOneWins(t *testing.T) {
	f := newLoginFixture(t)
	code := f.code(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.auth.Login(context.Background(), testPassword, code) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("same TOTP code accepted %d times", wins.Load())
	}
}

func TestLogin_LockoutAndExpiry(t *testing.T) {
	f := newLoginFixture(t)
	ctx := context.Background()
	for i := 0; i < MaxFailedAttempts; i++ {
		f.auth.Login(ctx, "wrong password!!", "000000")
	}
	if err := f.auth.Login(ctx, testPassword, f.code(t)); !errors.Is(err, ErrLocked) {
		t.Fatalf("correct credentials while locked: got %v", err)
	}
	f.now = f.now.Add(15*time.Minute + time.Second)
	if err := f.auth.Login(ctx, testPassword, f.code(t)); err != nil {
		t.Fatalf("after lockout expiry: got %v", err)
	}
}

func TestLogin_LockedStillHashesPassword(t *testing.T) {
	f := newLoginFixture(t)
	ctx := context.Background()
	for i := 0; i < MaxFailedAttempts; i++ {
		f.auth.Login(ctx, "wrong password!!", "000000")
	}
	var calls atomic.Int32
	orig := verifyPassword
	verifyPassword = func(encoded, pw string) (bool, error) { calls.Add(1); return orig(encoded, pw) }
	defer func() { verifyPassword = orig }()
	f.auth.Login(ctx, testPassword, f.code(t))
	if calls.Load() != 1 {
		t.Fatalf("password hash computed %d times while locked, want 1", calls.Load())
	}
}

func TestLogin_NotConfiguredStillHashesPassword(t *testing.T) {
	var calls atomic.Int32
	orig := verifyPassword
	verifyPassword = func(encoded, pw string) (bool, error) { calls.Add(1); return orig(encoded, pw) }
	defer func() { verifyPassword = orig }()
	a := &Authenticator{Store: newTestStore(t), Now: time.Now}
	a.Login(context.Background(), testPassword, "123456")
	if calls.Load() != 1 {
		t.Fatalf("password hash computed %d times for an unconfigured account, want 1", calls.Load())
	}
}

// TestLogin_ParallelGuessesBoundedByThreshold proves the lock is
// enforced by the same atomic statement that counts the attempt: no
// matter how many guesses arrive at once, at most MaxFailedAttempts are
// evaluated, and correct credentials afterwards are refused.
func TestLogin_ParallelGuessesBoundedByThreshold(t *testing.T) {
	f := newLoginFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 3*MaxFailedAttempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.auth.Login(ctx, "wrong password!!", "000000")
		}()
	}
	wg.Wait()
	// Every evaluated guess is counted in the database; a guess refused
	// as locked is not. So the counter is exactly how many guesses ran.
	acc, _, _ := f.store.Get(ctx)
	if acc.FailedAttempts > MaxFailedAttempts {
		t.Fatalf("%d guesses evaluated, want at most %d", acc.FailedAttempts, MaxFailedAttempts)
	}
	if err := f.auth.Login(ctx, testPassword, f.code(t)); !errors.Is(err, ErrLocked) {
		t.Fatalf("correct credentials after the burst: got %v, want ErrLocked", err)
	}
}

// TestLogin_ExpiredLockDoesNotRelockOnOneTypo proves one mistake after
// a lockout expires does not immediately lock the account again.
func TestLogin_ExpiredLockDoesNotRelockOnOneTypo(t *testing.T) {
	f := newLoginFixture(t)
	ctx := context.Background()
	for i := 0; i < MaxFailedAttempts; i++ {
		f.auth.Login(ctx, "wrong password!!", "000000")
	}
	f.now = f.now.Add(15*time.Minute + time.Second)
	if err := f.auth.Login(ctx, "wrong password!!", "000000"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("typo after expiry: got %v", err)
	}
	if err := f.auth.Login(ctx, testPassword, f.code(t)); err != nil {
		t.Fatalf("correct login after one typo: got %v", err)
	}
}

// TestLogin_HashConcurrencyIsBounded proves unauthenticated login
// requests cannot run unlimited PBKDF2 computations at once.
func TestLogin_HashConcurrencyIsBounded(t *testing.T) {
	f := newLoginFixture(t)
	var inFlight, peak atomic.Int32
	orig := verifyPassword
	verifyPassword = func(encoded, pw string) (bool, error) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		return false, nil
	}
	defer func() { verifyPassword = orig }()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.auth.Login(context.Background(), "x", "000000") }()
	}
	wg.Wait()
	if int(peak.Load()) > cap(hashSlots) {
		t.Fatalf("%d password hashes ran at once, limit is %d", peak.Load(), cap(hashSlots))
	}
}

// TestAuthenticate_ReportsRecoveryCodeUse proves a recovery-code login
// is distinguishable (for the audit log) and reports how many remain.
func TestAuthenticate_ReportsRecoveryCodeUse(t *testing.T) {
	f := newLoginFixture(t)
	ctx := context.Background()
	res, err := f.auth.Authenticate(ctx, testPassword, f.recovery[0])
	if err != nil || !res.RecoveryCode || res.RecoveryCodesLeft != 7 {
		t.Fatalf("recovery login: %+v %v", res, err)
	}
	res, err = f.auth.Authenticate(ctx, testPassword, f.code(t))
	if err != nil || res.RecoveryCode {
		t.Fatalf("TOTP login: %+v %v", res, err)
	}
}

// TestLogin_WrongPasswordDoesTheSameCodeWork proves a wrong password
// still runs the recovery-code lookup, so response time does not reveal
// whether the password was right.
func TestLogin_WrongPasswordDoesTheSameCodeWork(t *testing.T) {
	f := newLoginFixture(t)
	var lookups atomic.Int32
	orig := lookupRecovery
	lookupRecovery = func(s *Store, ctx context.Context, hash string) (bool, error) {
		lookups.Add(1)
		return orig(s, ctx, hash)
	}
	defer func() { lookupRecovery = orig }()
	f.auth.Login(context.Background(), "wrong password!!", "abcdefghjk")
	if lookups.Load() != 1 {
		t.Fatalf("recovery lookup ran %d times for a wrong password, want 1", lookups.Load())
	}
}

// TestDummyHashComputedAtStartup proves the first login on an
// unconfigured server does not pay for two PBKDF2 runs.
func TestDummyHashComputedAtStartup(t *testing.T) {
	if dummyHash == "" {
		t.Fatal("dummy hash not computed at package initialisation")
	}
}
