package admin

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return &Store{DB: database}
}

func TestStore_GetOnEmptyDB(t *testing.T) {
	st := newTestStore(t)
	if _, found, err := st.Get(context.Background()); err != nil || found {
		t.Fatalf("found=%v err=%v, want not found", found, err)
	}
}

func TestStore_SetPasswordAndTOTP(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.SetPassword(ctx, "hash1"); err != nil {
		t.Fatal(err)
	}
	acc, found, err := st.Get(ctx)
	if err != nil || !found || acc.PasswordHash != "hash1" || acc.TOTPSecret != "" {
		t.Fatalf("after SetPassword: %+v found=%v err=%v", acc, found, err)
	}
	_, hashes, _ := NewRecoveryCodes()
	if err := st.SetTOTP(ctx, "SECRET", hashes); err != nil {
		t.Fatal(err)
	}
	acc, _, _ = st.Get(ctx)
	if acc.TOTPSecret != "SECRET" || acc.PasswordHash != "hash1" {
		t.Fatalf("after SetTOTP: %+v", acc)
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM admin_recovery_codes`).Scan(&n)
	if n != 8 {
		t.Fatalf("want 8 recovery codes stored, got %d", n)
	}
}

func TestStore_ReserveAttemptLocksAtThreshold(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	st.SetPassword(ctx, "h")
	now := time.Unix(1_700_000_000, 0)
	for i := 1; i <= MaxFailedAttempts; i++ {
		ok, err := st.ReserveAttempt(ctx, now)
		if err != nil || !ok {
			t.Fatalf("attempt %d: ok=%v err=%v", i, ok, err)
		}
	}
	if ok, _ := st.ReserveAttempt(ctx, now); ok {
		t.Fatal("attempt beyond the threshold was reserved")
	}
	acc, _, _ := st.Get(ctx)
	if !acc.LockedUntil.Equal(now.Add(15*time.Minute)) || acc.FailedAttempts != MaxFailedAttempts {
		t.Fatalf("got %+v", acc)
	}
	if err := st.RecordSuccess(ctx, 42); err != nil {
		t.Fatal(err)
	}
	acc, _, _ = st.Get(ctx)
	if acc.FailedAttempts != 0 || !acc.LockedUntil.IsZero() || acc.TOTPLastStep != 42 {
		t.Fatalf("after success: %+v", acc)
	}
}

func TestStore_ReserveAttemptResetsAfterLockExpires(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	st.SetPassword(ctx, "h")
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < MaxFailedAttempts; i++ {
		st.ReserveAttempt(ctx, now)
	}
	later := now.Add(15*time.Minute + time.Second)
	if ok, _ := st.ReserveAttempt(ctx, later); !ok {
		t.Fatal("attempt refused after the lock expired")
	}
	acc, _, _ := st.Get(ctx)
	if acc.FailedAttempts != 1 || !acc.LockedUntil.IsZero() {
		t.Fatalf("counter not reset after expiry: %+v", acc)
	}
}

func TestStore_UseRecoveryCodeOnce(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	st.SetPassword(ctx, "h")
	plain, hashes, _ := NewRecoveryCodes()
	st.SetTOTP(ctx, "S", hashes)
	h := HashRecoveryCode(plain[0])
	if ok, err := st.UseRecoveryCode(ctx, h, time.Now()); err != nil || !ok {
		t.Fatalf("first use: ok=%v err=%v", ok, err)
	}
	if ok, _ := st.UseRecoveryCode(ctx, h, time.Now()); ok {
		t.Fatal("recovery code accepted twice")
	}
	if ok, _ := st.UseRecoveryCode(ctx, HashRecoveryCode("nope"), time.Now()); ok {
		t.Fatal("unknown recovery code accepted")
	}
}

func TestStore_SetTOTPReplacesRecoveryCodesAndResetsStep(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	st.SetPassword(ctx, "h")
	oldPlain, oldHashes, _ := NewRecoveryCodes()
	st.SetTOTP(ctx, "A", oldHashes)
	st.RecordSuccess(ctx, 99)
	_, newHashes, _ := NewRecoveryCodes()
	st.SetTOTP(ctx, "B", newHashes)
	acc, _, _ := st.Get(ctx)
	if acc.TOTPLastStep != 0 {
		t.Fatalf("last step not reset: %d", acc.TOTPLastStep)
	}
	if ok, _ := st.UseRecoveryCode(ctx, HashRecoveryCode(oldPlain[0]), time.Now()); ok {
		t.Fatal("old recovery code still valid after SetTOTP")
	}
}

func TestStore_ReserveAttempt_ConcurrentNeverExceedsThreshold(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	st.SetPassword(ctx, "h")
	var reserved atomic.Int32
	var wg sync.WaitGroup
	now := time.Now()
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := st.ReserveAttempt(ctx, now)
			if err != nil {
				t.Error(err)
			}
			if ok {
				reserved.Add(1)
			}
		}()
	}
	wg.Wait()
	if reserved.Load() != MaxFailedAttempts {
		t.Fatalf("reserved %d attempts, want exactly %d", reserved.Load(), MaxFailedAttempts)
	}
}
