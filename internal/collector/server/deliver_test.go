package server

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert/notifiers"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/rules"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

type countingNotifier struct {
	mu   sync.Mutex
	sent []alert.Notification
}

func (c *countingNotifier) Send(ctx context.Context, n alert.Notification) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, n)
	return nil
}

// TestDeliver_SendsOnceThenStaysQuiet proves the alert loop no longer
// repeats the same alert every cycle, announces resolution, and treats
// muted records as silent.
func TestDeliver_SendsOnceThenStaysQuiet(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st, rs := store.NewSQLite(database), rules.NewSQLite(database)
	now := time.Now()
	rec := checker.ExpiryRecord{Source: "a:443", Name: "a", Kind: "certificate", ExpiresAt: now.Add(2 * 24 * time.Hour)}
	st.SaveRecords(ctx, "web-01", []checker.ExpiryRecord{rec}, now)

	engine := &alert.Engine{Store: st, Rules: rs, Thresholds: alert.DefaultThresholds()}
	state := &alert.StateStore{DB: database, ReminderCritical: 24 * time.Hour}
	n := &countingNotifier{}

	for i := 0; i < 3; i++ {
		deliver(ctx, engine, state, []notifiers.Notifier{n}, now.Add(time.Duration(i)*time.Hour))
	}
	if len(n.sent) != 1 || n.sent[0].Severity != alert.SeverityCritical {
		t.Fatalf("want exactly 1 critical alert over 3 cycles, got %+v", n.sent)
	}

	rec.ExpiresAt = now.Add(300 * 24 * time.Hour) // renewed
	st.SaveRecords(ctx, "web-01", []checker.ExpiryRecord{rec}, now.Add(4*time.Hour))
	deliver(ctx, engine, state, []notifiers.Notifier{n}, now.Add(4*time.Hour))
	if len(n.sent) != 2 || !n.sent[1].Resolved {
		t.Fatalf("want a resolved message after renewal, got %+v", n.sent)
	}

	rec.ExpiresAt = now.Add(24 * time.Hour)
	st.SaveRecords(ctx, "web-01", []checker.ExpiryRecord{rec}, now.Add(5*time.Hour))
	rs.Upsert(ctx, rules.Rule{Source: "a:443", Name: "a", Kind: "certificate", Muted: true})
	deliver(ctx, engine, state, []notifiers.Notifier{n}, now.Add(5*time.Hour))
	if len(n.sent) != 2 {
		t.Fatalf("muted record alerted: %+v", n.sent[2:])
	}
}

func TestConfig_AlertDefaults(t *testing.T) {
	var c Config
	if c.reminderCritical() != 24*time.Hour || c.reminderWarning() != 0 || c.checkerFailThreshold() != 3 || c.agentStaleAfter() != 3*time.Hour {
		t.Fatal("wrong defaults")
	}
	zero, six := 0, 6
	c = Config{ReminderCriticalHours: &zero, ReminderWarningHours: &six, CheckerFailThreshold: 5, AgentStaleHours: 12}
	if c.reminderCritical() != 0 || c.reminderWarning() != 6*time.Hour || c.checkerFailThreshold() != 5 || c.agentStaleAfter() != 12*time.Hour {
		t.Fatal("explicit values ignored")
	}
}

type failingNotifier struct{ fail bool }

func (f *failingNotifier) Send(ctx context.Context, n alert.Notification) error {
	if f.fail {
		return errors.New("slack 503")
	}
	return nil
}

// TestDeliver_FailedDeliveryIsRetried proves an alert that no notifier
// managed to deliver is tried again next cycle instead of being lost.
func TestDeliver_FailedDeliveryIsRetried(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st, rs := store.NewSQLite(database), rules.NewSQLite(database)
	now := time.Now()
	st.SaveRecords(ctx, "web-01", []checker.ExpiryRecord{{Source: "a:443", Name: "a", Kind: "certificate", ExpiresAt: now.Add(20 * 24 * time.Hour)}}, now)
	engine := &alert.Engine{Store: st, Rules: rs, Thresholds: alert.DefaultThresholds()}
	state := &alert.StateStore{DB: database, ReminderCritical: 24 * time.Hour}

	broken := &failingNotifier{fail: true}
	deliver(ctx, engine, state, []notifiers.Notifier{broken}, now)
	ok := &countingNotifier{}
	deliver(ctx, engine, state, []notifiers.Notifier{ok}, now.Add(time.Hour))
	if len(ok.sent) != 1 || ok.sent[0].Severity != alert.SeverityWarning {
		t.Fatalf("warning lost after a failed delivery: %+v", ok.sent)
	}
}

// TestDeliver_GoneItemResolvesItsAlert: an item that stops being
// reported (deleted, rotated away) gets one "resolved" notification and
// its alert state is cleared, instead of alerting forever or going quiet
// with a stale open alert.
func TestDeliver_GoneItemResolvesItsAlert(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st, rs := store.NewSQLite(database), rules.NewSQLite(database)
	now := time.Now()
	old := checker.ExpiryRecord{Source: "azure://graph.microsoft.com/applications/x", Name: "App · prod · 11111111", Kind: "secret", ExpiresAt: now.Add(2 * 24 * time.Hour)}
	st.SaveResult(ctx, "agent-1", "azure", []checker.ExpiryRecord{old}, now, true)
	engine := &alert.Engine{Store: st, Rules: rs, Thresholds: alert.DefaultThresholds()}
	state := &alert.StateStore{DB: database, ReminderCritical: 24 * time.Hour}
	n := &countingNotifier{}
	deliver(ctx, engine, state, []notifiers.Notifier{n}, now)

	st.SaveResult(ctx, "agent-1", "azure", nil, now.Add(time.Minute), true) // rotated away
	deliver(ctx, engine, state, []notifiers.Notifier{n}, now.Add(time.Hour))
	deliver(ctx, engine, state, []notifiers.Notifier{n}, now.Add(2*time.Hour))
	if len(n.sent) != 2 || !n.sent[1].Resolved || n.sent[1].Record.Name != old.Name || n.sent[1].Record.Source != old.Source {
		t.Fatalf("want alert + one resolution for the gone item, got %+v", n.sent)
	}
}
