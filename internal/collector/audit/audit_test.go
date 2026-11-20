package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
)

func newTestStore(t *testing.T, now time.Time) *Store {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return &Store{DB: database, Now: func() time.Time { return now }}
}

func TestStore_LogAndList(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	st := newTestStore(t, now)

	if err := st.Log(ctx, "admin", "login", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.Log(ctx, "alice@example.com", "mute", "tls://host:443", "false", "true", "renewing next week"); err != nil {
		t.Fatal(err)
	}

	entries, err := st.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	// Newest first.
	got := entries[0]
	if got.Actor != "alice@example.com" || got.Action != "mute" || got.Target != "tls://host:443" ||
		got.OldValue != "false" || got.NewValue != "true" || got.Reason != "renewing next week" || !got.At.Equal(now) {
		t.Fatalf("unexpected entry: %+v", got)
	}
	if entries[1].Actor != "admin" || entries[1].Action != "login" {
		t.Fatalf("unexpected entry: %+v", entries[1])
	}
}

func TestStore_ListRespectsLimit(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t, time.Unix(1_700_000_000, 0))
	for i := 0; i < 5; i++ {
		if err := st.Log(ctx, "admin", "login", "", "", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := st.List(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
}

func TestStore_ListEmpty(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t, time.Unix(1_700_000_000, 0))
	entries, err := st.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("got %d entries, want 0", len(entries))
	}
}
