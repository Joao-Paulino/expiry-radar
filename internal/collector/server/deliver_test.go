package server

import (
	"context"
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
