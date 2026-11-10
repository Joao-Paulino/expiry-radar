package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
)

func newTestStore(t *testing.T) *SQLite {
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return NewSQLite(database)
}

func TestSQLite_ListCurrent_ReturnsLatestPerKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	old := checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(72 * time.Hour)}
	if err := s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{old}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // ensure a distinct checked_at
	newer := old
	newer.ExpiresAt = time.Now().Add(48 * time.Hour)
	if err := s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{newer}); err != nil {
		t.Fatal(err)
	}

	current, err := s.ListCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(current) != 1 {
		t.Fatalf("expected 1 current record, got %d", len(current))
	}
	if !current[0].ExpiresAt.Equal(newer.ExpiresAt) {
		t.Fatalf("ListCurrent returned stale ExpiresAt %v, want %v", current[0].ExpiresAt, newer.ExpiresAt)
	}
}

func TestSQLite_History_ReturnsAllSnapshotsOrdered(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	rec := checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(72 * time.Hour)}
	s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{rec})
	time.Sleep(10 * time.Millisecond)
	rec.ExpiresAt = time.Now().Add(48 * time.Hour)
	s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{rec})

	hist, err := s.History(ctx, "a", "b", "certificate")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("expected 2 history rows, got %d", len(hist))
	}
	if !hist[0].CheckedAt.Before(hist[1].CheckedAt) {
		t.Fatal("expected history ordered oldest first")
	}
}

func TestSQLite_RecordCheckerHealth_SuccessAndFailure(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.RecordCheckerHealth(ctx, "tls-checker", "agent-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCheckerHealth(ctx, "tls-checker", "agent-1", errors.New("boom")); err != nil {
		t.Fatal(err)
	}
	health, err := s.CheckerHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(health) != 1 || health[0].LastError != "boom" {
		t.Fatalf("got %+v, want LastError=boom", health)
	}
	if health[0].LastSuccessAt.IsZero() {
		t.Fatal("expected LastSuccessAt to be preserved from the earlier successful call")
	}
}
