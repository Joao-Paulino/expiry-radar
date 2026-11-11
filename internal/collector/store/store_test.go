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
	if err := s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{old}, time.Now()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // ensure a distinct checked_at
	newer := old
	newer.ExpiresAt = time.Now().Add(48 * time.Hour)
	if err := s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{newer}, time.Now()); err != nil {
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

// TestSQLite_ListCurrent_LateRetryWithOlderCheckedAtDoesNotOverwriteNewer
// is the Plan's Review Focus #2: a queued batch that is retried and
// lands at the Collector *after* a newer batch for the same
// (source, name, kind) must not make ListCurrent regress to the
// stale data, even though it was *inserted* later. ListCurrent must
// key off the check's own timestamp (checked_at, supplied by the
// caller), not insertion order or receive time.
func TestSQLite_ListCurrent_LateRetryWithOlderCheckedAtDoesNotOverwriteNewer(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	renewed := checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(365 * 24 * time.Hour)}
	renewedCheckedAt := time.Now()
	if err := s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{renewed}, renewedCheckedAt); err != nil {
		t.Fatal(err)
	}

	// A batch the agent checked BEFORE the renewal, but which only
	// arrives (and is inserted) after it — e.g. a retried batch from
	// the agent's local queue.
	stale := checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(48 * time.Hour)}
	staleCheckedAt := renewedCheckedAt.Add(-time.Hour)
	if err := s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{stale}, staleCheckedAt); err != nil {
		t.Fatal(err)
	}

	current, err := s.ListCurrent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(current) != 1 {
		t.Fatalf("expected 1 current record, got %d", len(current))
	}
	if !current[0].ExpiresAt.Equal(renewed.ExpiresAt) {
		t.Fatalf("ListCurrent returned the late, stale-checked record (ExpiresAt=%v); want the newer check's ExpiresAt=%v", current[0].ExpiresAt, renewed.ExpiresAt)
	}
}

func TestSQLite_History_ReturnsAllSnapshotsOrdered(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	rec := checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(72 * time.Hour)}
	s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{rec}, time.Now())
	time.Sleep(10 * time.Millisecond)
	rec.ExpiresAt = time.Now().Add(48 * time.Hour)
	s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{rec}, time.Now())

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

// TestSQLite_CheckerHealthIsPerAgent proves one agent's success never
// hides another agent's failure, and that consecutive failures are
// counted per agent and reset by a success.
func TestSQLite_CheckerHealthIsPerAgent(t *testing.T) {
	ctx := context.Background()
	st := newHealthTestStore(t)
	boom := errors.New("dial tcp: timeout")
	st.RecordCheckerHealth(ctx, "tls", "agent-a", boom)
	st.RecordCheckerHealth(ctx, "tls", "agent-a", boom)
	st.RecordCheckerHealth(ctx, "tls", "agent-b", nil)

	hs, err := st.CheckerHealth(ctx)
	if err != nil || len(hs) != 2 {
		t.Fatalf("got %+v, %v; want 2 entries", hs, err)
	}
	byAgent := map[string]CheckerHealth{}
	for _, h := range hs {
		byAgent[h.ReportedBy] = h
	}
	a, b := byAgent["agent-a"], byAgent["agent-b"]
	if a.ConsecutiveFailures != 2 || a.LastError != boom.Error() || !a.LastSuccessAt.IsZero() || a.LastSeenAt.IsZero() {
		t.Fatalf("agent-a: %+v", a)
	}
	if b.ConsecutiveFailures != 0 || b.LastSuccessAt.IsZero() || b.LastSeenAt.IsZero() {
		t.Fatalf("agent-b: %+v", b)
	}

	st.RecordCheckerHealth(ctx, "tls", "agent-a", nil)
	hs, _ = st.CheckerHealth(ctx)
	for _, h := range hs {
		if h.ReportedBy == "agent-a" && (h.ConsecutiveFailures != 0 || h.LastError != "" || h.LastSuccessAt.IsZero()) {
			t.Fatalf("agent-a not reset by success: %+v", h)
		}
	}
}

func newHealthTestStore(t *testing.T) *SQLite {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return NewSQLite(database)
}

// TestSQLite_AgentsSeenAndForgotten proves every batch marks its agent
// as seen (even with no checker results) and that forgetting an agent
// removes its health and its alert state.
func TestSQLite_AgentsSeenAndForgotten(t *testing.T) {
	ctx := context.Background()
	st := newHealthTestStore(t)
	if err := st.TouchAgent(ctx, "web-01"); err != nil {
		t.Fatal(err)
	}
	st.RecordCheckerHealth(ctx, "tls", "web-02", errors.New("x"))
	st.TouchAgent(ctx, "web-02")
	st.db.Exec(`INSERT INTO alert_state (alert_key, severity, last_sent_at) VALUES ('agent|web-02','critical',1), ('checker|web-02|tls','critical',1), ('agent|web-03','critical',1)`)

	agents, err := st.Agents(ctx)
	if err != nil || len(agents) != 2 || agents[0].AgentID != "web-01" || agents[0].LastSeenAt.IsZero() {
		t.Fatalf("got %+v, %v", agents, err)
	}
	if err := st.ForgetAgent(ctx, "web-02"); err != nil {
		t.Fatal(err)
	}
	agents, _ = st.Agents(ctx)
	hs, _ := st.CheckerHealth(ctx)
	var keys int
	st.db.QueryRow(`SELECT COUNT(*) FROM alert_state`).Scan(&keys)
	if len(agents) != 1 || len(hs) != 0 || keys != 1 {
		t.Fatalf("after forget: agents=%+v health=%+v alert keys=%d (want 1 left: agent|web-03)", agents, hs, keys)
	}
}
