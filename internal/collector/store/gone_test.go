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

func rec(name string) checker.ExpiryRecord {
	return checker.ExpiryRecord{Source: "vault://v/secret", Name: name, Kind: "secret", ExpiresAt: time.Now().Add(5 * 24 * time.Hour)}
}

func currentNames(t *testing.T, s *SQLite) map[string]bool {
	t.Helper()
	cur, err := s.ListCurrent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]bool{}
	for _, r := range cur {
		m[r.ReportedBy+"/"+r.Name] = true
	}
	return m
}

// An item missing from a later complete run of the same agent and
// checker is gone (deleted, renamed, rotated away): it must stop being
// current, so it stops alerting.
func TestListCurrent_ItemMissingFromCompleteRunIsGone(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour)
	if err := s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("old"), rec("kept")}, t0, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("kept")}, t0.Add(time.Minute), true); err != nil {
		t.Fatal(err)
	}
	if got := currentNames(t, s); !got["agent-1/old"] {
		t.Fatalf("hidden after one run without it (a load balancer may alternate): %v", got)
	}
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("kept")}, t0.Add(2*time.Minute), true)
	got := currentNames(t, s)
	if got["agent-1/old"] || !got["agent-1/kept"] {
		t.Fatalf("current: %v", got)
	}
}

// A failing run may be partial (one vault unreachable): absence there
// proves nothing, so the item stays current.
func TestListCurrent_FailedRunDoesNotHideItems(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour)
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("a"), rec("b")}, t0, true)
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("a")}, t0.Add(time.Minute), false)
	if got := currentNames(t, s); !got["agent-1/b"] {
		t.Fatalf("item hidden by a partial run: %v", got)
	}
}

// A complete run with no records (everything deleted) clears the checker.
func TestListCurrent_EmptyCompleteRunClearsChecker(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour)
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("a")}, t0, true)
	s.SaveResult(ctx, "agent-1", "vault", nil, t0.Add(time.Minute), true)
	s.SaveResult(ctx, "agent-1", "vault", nil, t0.Add(2*time.Minute), true)
	if got := currentNames(t, s); len(got) != 0 {
		t.Fatalf("want nothing current, got %v", got)
	}
}

// Other checkers and other agents are independent; a late retried
// (older) complete batch does not move the clock back.
func TestListCurrent_GoneIsPerAgentAndChecker(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour)
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("v")}, t0, true)
	s.SaveResult(ctx, "agent-1", "tls-checker", []checker.ExpiryRecord{rec("t")}, t0, true)
	s.SaveResult(ctx, "agent-2", "vault", []checker.ExpiryRecord{rec("v2")}, t0, true)
	s.SaveResult(ctx, "agent-1", "vault", nil, t0.Add(2*time.Minute), true)                            // agent-1 vault: all gone
	s.SaveResult(ctx, "agent-1", "vault", nil, t0.Add(3*time.Minute), true)                            // twice
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("v")}, t0.Add(time.Minute), true) // late retry of an older batch
	got := currentNames(t, s)
	if got["agent-1/v"] || !got["agent-1/t"] || !got["agent-2/v2"] {
		t.Fatalf("current: %v", got)
	}
}

// Rows written before this change have no checker name: they are gone
// once the agent has a newer complete run of any checker and nobody
// reports the item again.
func TestListCurrent_LegacyRowsWithoutChecker(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour)
	s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{rec("legacy-gone"), rec("legacy-kept")}, t0)
	if got := currentNames(t, s); !got["agent-1/legacy-gone"] {
		t.Fatal("legacy row hidden before any complete run")
	}
	s.RecordCheckerHealth(ctx, "vault", "agent-1", nil)
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("legacy-kept")}, t0.Add(time.Minute), true)
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("legacy-kept")}, t0.Add(2*time.Minute), true)
	got := currentNames(t, s)
	if got["agent-1/legacy-gone"] || !got["agent-1/legacy-kept"] {
		t.Fatalf("current: %v", got)
	}
}

// Databases created by older versions gain the new column on open.
func TestMigrate_AddsCheckerNameColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	database, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	database.Close()
	database, err = db.Open(path) // second open: migration is idempotent
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var n int
	database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('expiry_records') WHERE name = 'checker_name'`).Scan(&n)
	if n != 1 {
		t.Fatal("checker_name column missing")
	}
}

// A forgotten (decommissioned) agent's items stop being current too;
// they come back if the agent reports again.
func TestListCurrent_ForgottenAgentItemsAreGone(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("a")}, time.Now().Add(-time.Hour), true)
	s.SaveResult(ctx, "agent-2", "vault", []checker.ExpiryRecord{rec("b")}, time.Now().Add(-time.Hour), true)
	if err := s.ForgetAgent(ctx, "agent-1"); err != nil {
		t.Fatal(err)
	}
	if got := currentNames(t, s); got["agent-1/a"] || !got["agent-2/b"] {
		t.Fatalf("after forget: %v", got)
	}
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("a")}, time.Now().Add(time.Minute), true)
	if got := currentNames(t, s); !got["agent-1/a"] {
		t.Fatalf("agent reporting again: %v", got)
	}
}

// Another agent still reporting the item keeps it current, even if the
// newest row came from an agent that no longer sees it.
func TestListCurrent_OtherAgentStillReporting(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour)
	s.SaveResult(ctx, "agent-b", "tls-checker", []checker.ExpiryRecord{rec("shared")}, t0, true)
	s.SaveResult(ctx, "agent-a", "tls-checker", []checker.ExpiryRecord{rec("shared")}, t0.Add(10*time.Minute), true)
	s.SaveResult(ctx, "agent-a", "tls-checker", nil, t0.Add(20*time.Minute), true)
	s.SaveResult(ctx, "agent-a", "tls-checker", nil, t0.Add(30*time.Minute), true)
	if got := currentNames(t, s); !got["agent-b/shared"] {
		t.Fatalf("item still reported by agent-b hidden: %v", got)
	}
}

// Old-version rows of a failing checker must not be hidden by another
// checker's success.
func TestListCurrent_LegacyRowsKeptWhileACheckerFails(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour)
	s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{rec("legacy-vault")}, t0)
	s.RecordCheckerHealth(ctx, "vault", "agent-1", errors.New("sealed"))
	s.RecordCheckerHealth(ctx, "tls-checker", "agent-1", nil)
	for i := 1; i <= 2; i++ {
		s.SaveResult(ctx, "agent-1", "tls-checker", nil, t0.Add(time.Duration(i)*time.Minute), true)
		s.SaveResult(ctx, "agent-1", "vault", nil, t0.Add(time.Duration(i)*time.Minute), false)
	}
	if got := currentNames(t, s); !got["agent-1/legacy-vault"] {
		t.Fatalf("legacy item of a failing checker hidden: %v", got)
	}
}

// Forget uses the agent's own clock: an agent running behind the
// collector that reports again after being forgotten is shown.
func TestListCurrent_ForgottenAgentWithSlowClockComesBack(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	slow := time.Now().Add(-2 * time.Hour)
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("a")}, slow, true)
	s.ForgetAgent(ctx, "agent-1")
	s.SaveResult(ctx, "agent-1", "vault", []checker.ExpiryRecord{rec("a")}, slow.Add(time.Minute), true)
	if got := currentNames(t, s); !got["agent-1/a"] {
		t.Fatalf("agent with a slow clock hidden after reporting again: %v", got)
	}
}
