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
	for i := 0; i < 5; i++ {
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
	for i := 0; i < 5; i++ {
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
